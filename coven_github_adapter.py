import base64
import hashlib
import hmac
import json
import os
import subprocess
import tempfile
import time
import traceback
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen


ROOT_DIR = Path(__file__).resolve().parent
STATE_DIR = Path(os.environ.get("COVEN_GITHUB_STATE_DIR", ROOT_DIR / "coven-github-state"))
DELIVERIES_DIR = STATE_DIR / "deliveries"
TASKS_DIR = STATE_DIR / "tasks"
WORKSPACES_DIR = STATE_DIR / "workspaces"
ATTEMPTS_DIR = STATE_DIR / "attempts"
POLICY_PATH = Path(os.environ.get("COVEN_GITHUB_POLICY_PATH", ROOT_DIR / "coven-github-policy.json"))
PRIVATE_KEY_PATH = Path(
    os.environ.get("GITHUB_APP_PRIVATE_KEY_PATH", ROOT_DIR / ".coven-github-private-key.pem")
)
APP_ID = os.environ.get("GITHUB_APP_ID", "").strip()
WEBHOOK_SECRET = (
    os.environ.get("GITHUB_WEBHOOK_SECRET") or os.environ.get("WEBHOOK_SECRET", "")
).strip()
COVEN_CODE_BIN = os.environ.get("COVEN_CODE_BIN", "coven-code").strip() or "coven-code"
COVEN_CODE_MODEL = os.environ.get("COVEN_CODE_MODEL", "gpt-5.5").strip()


def env_int(name, default, minimum=0, maximum=10):
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    return max(minimum, min(maximum, value))


MAX_REVIEW_FIX_LOOPS = env_int("COVEN_REVIEW_FIX_LOOPS", 0, minimum=0, maximum=5)


def account_home():
    try:
        import pwd

        return Path(pwd.getpwuid(os.getuid()).pw_dir)
    except Exception:
        return Path.home()


def configured_codex_tokens_path():
    configured = os.environ.get("COVEN_CODE_CODEX_TOKENS_PATH", "").strip()
    if configured:
        return Path(configured).expanduser()
    return account_home() / ".coven-code" / "codex_tokens.json"


CODEX_TOKENS_PATH = configured_codex_tokens_path()

for directory in (DELIVERIES_DIR, TASKS_DIR, WORKSPACES_DIR, ATTEMPTS_DIR):
    directory.mkdir(parents=True, exist_ok=True)


DEFAULT_POLICY = {
    "version": 1,
    "installations": {},
}


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def read_json(path, default):
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except FileNotFoundError:
        return default


def write_json_atomic(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(value, handle, sort_keys=True, indent=2)
            handle.write("\n")
        os.replace(tmp_name, str(path))
    finally:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)


def b64url(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def sign_rs256(message):
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding

    key_data = PRIVATE_KEY_PATH.read_bytes()
    private_key = serialization.load_pem_private_key(key_data, password=None)
    return private_key.sign(message, padding.PKCS1v15(), hashes.SHA256())


def github_app_jwt():
    if not APP_ID:
        raise RuntimeError("GITHUB_APP_ID is required")
    now = int(time.time())
    header = {"alg": "RS256", "typ": "JWT"}
    payload = {"iat": now - 60, "exp": now + 540, "iss": APP_ID}
    signing_input = (
        b64url(json.dumps(header, separators=(",", ":")).encode("utf-8"))
        + "."
        + b64url(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    ).encode("ascii")
    return signing_input.decode("ascii") + "." + b64url(sign_rs256(signing_input))


def github_request(method, url, token, body=None):
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": "Bearer " + token,
        "User-Agent": "coven-github-hosted-prototype",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    request = Request(url, data=data, headers=headers, method=method)
    try:
        with urlopen(request, timeout=30) as response:
            raw = response.read().decode("utf-8")
            return json.loads(raw) if raw else {}
    except HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError("GitHub API {} {} failed: {}".format(method, url, raw))


def installation_token(installation_id):
    app_token = github_app_jwt()
    response = github_request(
        "POST",
        "https://api.github.com/app/installations/{}/access_tokens".format(installation_id),
        app_token,
        {},
    )
    token = response.get("token")
    if not token:
        raise RuntimeError("GitHub installation token response did not include token")
    return token


def load_policy():
    if not POLICY_PATH.exists():
        write_json_atomic(POLICY_PATH, DEFAULT_POLICY)
    return read_json(POLICY_PATH, DEFAULT_POLICY)


def repo_policy(payload):
    policy = load_policy()
    installation_id = str((payload.get("installation") or {}).get("id") or "")
    repository = payload.get("repository") or {}
    repo_id = str(repository.get("id") or "")
    installation = (policy.get("installations") or {}).get(installation_id) or {}
    repo = (installation.get("repositories") or {}).get(repo_id)
    return installation_id, repo_id, repo


def delivery_path(delivery_id):
    return DELIVERIES_DIR / (delivery_id + ".json")


def task_path(task_id):
    return TASKS_DIR / (task_id + ".json")


def header(environ, name, default=""):
    key = "HTTP_" + name.upper().replace("-", "_")
    return environ.get(key, default)


def json_response(start_response, status, body):
    payload = json.dumps(body, sort_keys=True).encode("utf-8")
    start_response(
        status,
        [
            ("Content-Type", "application/json"),
            ("Content-Length", str(len(payload))),
        ],
    )
    return [payload]


def read_request_body(environ):
    try:
        length = int(environ.get("CONTENT_LENGTH") or "0")
    except ValueError:
        length = 0
    return environ["wsgi.input"].read(length)


def verify_webhook_signature(secret, body, signature_header):
    if not secret:
        return False, "webhook secret not configured"
    if not signature_header:
        return False, "missing signature"
    prefix = "sha256="
    if not signature_header.startswith(prefix):
        return False, "invalid signature"
    expected = prefix + hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature_header):
        return False, "invalid signature"
    return True, None


def application(environ, start_response):
    method = environ.get("REQUEST_METHOD", "GET").upper()
    path = environ.get("PATH_INFO", "/")
    if method == "GET" and path in ("/", "/healthz"):
        return json_response(start_response, "200 OK", {"ok": True})
    if method != "POST" or path not in ("/", "/webhook"):
        return json_response(start_response, "404 Not Found", {"error": "not found"})

    body = read_request_body(environ)
    ok, error = verify_webhook_signature(
        WEBHOOK_SECRET,
        body,
        header(environ, "X-Hub-Signature-256"),
    )
    if not ok:
        status = "500 Internal Server Error" if error == "webhook secret not configured" else "401 Unauthorized"
        return json_response(start_response, status, {"error": error})

    event_name = header(environ, "X-GitHub-Event")
    if not event_name:
        return json_response(start_response, "400 Bad Request", {"error": "missing event"})

    try:
        payload = json.loads(body.decode("utf-8"))
    except json.JSONDecodeError:
        return json_response(start_response, "400 Bad Request", {"error": "invalid json"})

    delivery_id = header(environ, "X-GitHub-Delivery") or str(uuid.uuid4())
    result = route_delivery(event_name, delivery_id, payload, lambda message: print(message, flush=True))
    return json_response(start_response, "200 OK", result)


def payload_hash(payload):
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def delivery_record(delivery_id, event_name, payload):
    repository = payload.get("repository") or {}
    installation = payload.get("installation") or {}
    return {
        "delivery_id": delivery_id,
        "event": event_name,
        "action": payload.get("action"),
        "installation_id": installation.get("id"),
        "repository_id": repository.get("id"),
        "repository": repository.get("full_name"),
        "payload_hash": payload_hash(payload),
        "received_at": utc_now(),
        "state": "received",
        "issue_refs": ["OpenCoven/coven-github#2"],
    }


def mentioned(text, policy):
    normalized = (text or "").lower()
    for username in policy.get("bot_usernames") or []:
        if "@" + username.lower() in normalized:
            return True
    return False


def labels_include_trigger(labels, policy):
    wanted = set((policy.get("trigger_labels") or []))
    for label in labels or []:
        name = (label.get("name") if isinstance(label, dict) else str(label)).strip()
        if name in wanted:
            return True
    return False


def build_task_from_event(event_name, delivery_id, payload, policy):
    repository = payload.get("repository") or {}
    installation = payload.get("installation") or {}
    familiar = policy.get("familiar")
    base = {
        "task_id": delivery_id,
        "delivery_id": delivery_id,
        "created_at": utc_now(),
        "updated_at": utc_now(),
        "state": "queued",
        "attempts": 0,
        "installation_id": installation.get("id"),
        "repository_id": repository.get("id"),
        "repository": repository.get("full_name"),
        "clone_url": repository.get("clone_url")
        or "https://github.com/{}.git".format(repository.get("full_name")),
        "default_branch": repository.get("default_branch") or policy.get("default_branch") or "main",
        "familiar": familiar,
        "publication": policy.get("publication") or {"mode": "record_only"},
        "issue_refs": ["OpenCoven/coven-github#2", "OpenCoven/coven-github#7"],
    }
    if not familiar:
        return ignored(base, "missing_familiar_policy")

    if event_name == "issue_comment":
        issue = payload.get("issue") or {}
        comment = payload.get("comment") or {}
        if not mentioned(comment.get("body"), policy):
            return ignored(base, "issue_comment_without_mention")
        if issue.get("pull_request"):
            base.update(
                {
                    "trigger": "pr_mention",
                    "target": {
                        "kind": "pull_request",
                        "pr_number": int(issue.get("number") or 0),
                    },
                    "task": {
                        "kind": "respond_to_mention",
                        "issue_number": int(issue.get("number") or 0),
                        "comment_body": comment.get("body") or "",
                    },
                    "issue_refs": base["issue_refs"] + ["OpenCoven/coven-github#4"],
                }
            )
            return base
        base.update(
            {
                "trigger": "issue_mention",
                "task": {
                    "kind": "respond_to_mention",
                    "issue_number": int(issue.get("number") or 0),
                    "comment_body": comment.get("body") or "",
                },
                "issue_refs": base["issue_refs"] + ["OpenCoven/coven-github#4"],
            }
        )
        return base

    if event_name == "pull_request_review_comment":
        comment = payload.get("comment") or {}
        pull_request = payload.get("pull_request") or {}
        if not mentioned(comment.get("body"), policy):
            return ignored(base, "pr_review_comment_without_mention")
        base.update(
            {
                "trigger": "pr_review_comment",
                "task": {
                    "kind": "address_review_comment",
                    "pr_number": int(pull_request.get("number") or 0),
                    "comment_body": comment.get("body") or "",
                    "diff_hunk": comment.get("diff_hunk"),
                    "path": comment.get("path"),
                    "line": comment.get("line"),
                    "side": comment.get("side"),
                    "commit_id": comment.get("commit_id"),
                    "html_url": comment.get("html_url"),
                },
                "issue_refs": base["issue_refs"] + ["OpenCoven/coven-github#4"],
            }
        )
        return base

    if event_name == "issues":
        issue = payload.get("issue") or {}
        action = payload.get("action")
        if action not in ("assigned", "labeled", "opened"):
            return ignored(base, "unsupported_issue_action")
        if action == "labeled" and not labels_include_trigger(issue.get("labels"), policy):
            return ignored(base, "issue_label_not_enabled")
        base.update(
            {
                "trigger": "issue_assigned" if action == "assigned" else "issue_mention",
                "task": {
                    "kind": "fix_issue",
                    "issue_number": int(issue.get("number") or 0),
                    "issue_title": issue.get("title") or "",
                    "issue_body": issue.get("body") or "",
                },
                "issue_refs": base["issue_refs"] + ["OpenCoven/coven-github#4"],
            }
        )
        return base

    if event_name == "pull_request":
        pull_request = payload.get("pull_request") or {}
        base.update(
            {
                "state": "ignored",
                "ignored_reason": "pull_request_review_task_not_in_headless_contract_v1",
                "trigger": "pull_request",
                "target": {
                    "action": payload.get("action"),
                    "number": pull_request.get("number"),
                    "head_sha": (pull_request.get("head") or {}).get("sha"),
                    "head_ref": (pull_request.get("head") or {}).get("ref"),
                    "base_ref": (pull_request.get("base") or {}).get("ref"),
                },
                "issue_refs": base["issue_refs"] + ["OpenCoven/coven-github#10"],
            }
        )
        return base

    if event_name == "push":
        base.update(
            {
                "state": "ignored",
                "ignored_reason": "push_review_task_not_in_headless_contract_v1",
                "trigger": "push",
                "target": {
                    "ref": payload.get("ref"),
                    "before": payload.get("before"),
                    "after": payload.get("after"),
                    "commit_count": len(payload.get("commits") or []),
                },
                "issue_refs": base["issue_refs"] + ["OpenCoven/coven-github#10"],
            }
        )
        return base

    return ignored(base, "unsupported_event")


def ignored(base, reason):
    base["state"] = "ignored"
    base["ignored_reason"] = reason
    return base


def route_delivery(event_name, delivery_id, payload, debug):
    delivery_file = delivery_path(delivery_id)
    if delivery_file.exists():
        existing = read_json(delivery_file, {})
        return {
            "ok": True,
            "action": "duplicate_ignored",
            "delivery_id": delivery_id,
            "task_id": existing.get("task_id"),
            "state": existing.get("state"),
        }

    delivery = delivery_record(delivery_id, event_name, payload)
    installation_id, repo_id, policy = repo_policy(payload)
    if not policy:
        delivery["state"] = "ignored"
        delivery["routing_result"] = "no_policy_for_installation_repo"
        delivery["installation_id"] = installation_id or delivery.get("installation_id")
        delivery["repository_id"] = repo_id or delivery.get("repository_id")
        write_json_atomic(delivery_file, delivery)
        return {
            "ok": True,
            "action": "ignored",
            "delivery_id": delivery_id,
            "reason": "no_policy_for_installation_repo",
        }

    task = build_task_from_event(event_name, delivery_id, payload, policy)
    task["policy_snapshot"] = {
        "enabled_triggers": policy.get("enabled_triggers") or [],
        "publication": policy.get("publication") or {"mode": "record_only"},
    }
    write_json_atomic(task_path(task["task_id"]), task)

    delivery["task_id"] = task["task_id"]
    delivery["state"] = task["state"]
    delivery["routing_result"] = task.get("ignored_reason") or "queued"
    write_json_atomic(delivery_file, delivery)

    if task["state"] == "queued":
        try:
            run_task(task["task_id"], debug)
        except Exception:
            debug("COVEN GITHUB TASK RUN FAIL task_id={} {}".format(task["task_id"], traceback.format_exc()))

    return {
        "ok": True,
        "action": "accepted" if task["state"] != "ignored" else "ignored",
        "delivery_id": delivery_id,
        "task_id": task["task_id"],
        "state": read_json(task_path(task["task_id"]), task).get("state"),
        "reason": task.get("ignored_reason"),
        "queued": task["state"] == "queued",
    }


def run_command(args, cwd=None, env=None, timeout=300):
    proc = subprocess.run(
        args,
        cwd=cwd,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        text=True,
    )
    return {
        "args": args,
        "returncode": proc.returncode,
        "stdout": proc.stdout[-8000:],
        "stderr": proc.stderr[-8000:],
    }


def write_askpass(work_dir):
    script = work_dir / "git-askpass.sh"
    script.write_text("#!/bin/sh\nprintf '%s\\n' \"$COVEN_GIT_TOKEN\"\n", encoding="utf-8")
    script.chmod(0o700)
    return script


def session_brief(task, workspace, review_context=None, extra_audit_instruction=None):
    owner, name = (task["repository"] or "/").split("/", 1)
    brief = {
        "contract_version": "2",
        "trigger": task["trigger"],
        "repo": {
            "owner": owner,
            "name": name,
            "clone_url": task["clone_url"],
            "default_branch": task["default_branch"],
        },
        "task": task["task"],
        "familiar": task["familiar"],
        "workspace": {"root": str(workspace)},
    }
    if review_context:
        brief["review_context"] = review_context
        instruction = (
            "This run is evidence-backed. Review the supplied PR metadata and "
            "changed-file patches in review_context before responding. Cite the "
            "specific changed files you inspected in the result summary."
        )
        if extra_audit_instruction:
            instruction = instruction + "\n\n" + extra_audit_instruction
        brief["audit_instruction"] = instruction
    return brief


def run_coven_code_cycle(
    task,
    workspace,
    review_context,
    attempt_dir,
    env,
    cycle,
    extra_audit_instruction=None,
):
    suffix = "" if cycle == 0 else "-repair-{}".format(cycle)
    brief_path = attempt_dir / "session-brief{}.json".format(suffix)
    result_path = attempt_dir / "result{}.json".format(suffix)
    run_path = attempt_dir / "run{}.json".format(suffix)

    write_json_atomic(
        brief_path,
        session_brief(task, workspace, review_context, extra_audit_instruction),
    )
    run = run_command(
        [
            COVEN_CODE_BIN,
            "--headless",
            "--hosted-review",
            "--provider",
            "codex",
            "--model",
            COVEN_CODE_MODEL,
            "--context",
            str(brief_path),
            "--output",
            str(result_path),
        ],
        cwd=str(workspace),
        env=env,
        timeout=1800,
    )
    write_json_atomic(run_path, redacted_command_result(run))
    result = read_json(result_path, None) if result_path.exists() else None
    return {
        "cycle": cycle,
        "brief_path": brief_path,
        "result_path": result_path,
        "run_path": run_path,
        "run": run,
        "result": result,
    }


def review_findings(result):
    if not result:
        return []
    review = result.get("review") or {}
    mode = review.get("mode")
    if mode not in ("pull_request", "review_comment"):
        return []
    return review.get("findings") or []


def review_fix_instruction(findings, iteration, max_iterations):
    lines = [
        "Autofix review loop iteration {}/{}.".format(iteration, max_iterations),
        "The previous hosted review returned structured findings. Fix the findings below, run the relevant checks you can run safely, then perform another bounded review of the updated code using the required review sections.",
        "If a finding cannot be fixed safely, leave a clear limitation and explain the remaining blocker. Do not merely restate the findings.",
        "",
        "Findings to fix:",
    ]
    for index, finding in enumerate(findings[:10], start=1):
        location = finding.get("file") or "unknown file"
        if finding.get("line") is not None:
            location = "{}:{}".format(location, finding.get("line"))
        lines.append(
            "{}. [{}] `{}` {}".format(
                index,
                finding.get("severity") or "unknown",
                location,
                finding.get("title") or "Untitled finding",
            )
        )
        body = (finding.get("body") or "").strip()
        if body:
            lines.append("   Body: {}".format(body[:1200]))
        recommendation = (finding.get("recommendation") or "").strip()
        if recommendation:
            lines.append("   Recommendation: {}".format(recommendation[:1200]))
    if len(findings) > 10:
        lines.append("Only the first 10 findings are listed; inspect the prior result for the full set.")
    return "\n".join(lines)


def task_with_repair_request(task, instruction):
    copy = json.loads(json.dumps(task))
    task_data = copy.get("task") or {}
    explicit_request = (
        "\n\nPlease fix the review findings from the previous hosted review cycle. "
        "After fixing them, rerun relevant checks and produce another structured review.\n\n"
        + instruction
    )
    if "comment_body" in task_data:
        task_data["comment_body"] = (task_data.get("comment_body") or "") + explicit_request
    elif "issue_body" in task_data:
        task_data["issue_body"] = (task_data.get("issue_body") or "") + explicit_request
    copy["task"] = task_data
    return copy


def run_task(task_id, debug):
    path = task_path(task_id)
    task = read_json(path, {})
    if task.get("state") != "queued":
        return task

    task["state"] = "running"
    task["attempts"] = int(task.get("attempts") or 0) + 1
    task["updated_at"] = utc_now()
    write_json_atomic(path, task)

    attempt_dir = ATTEMPTS_DIR / task_id / str(task["attempts"])
    attempt_dir.mkdir(parents=True, exist_ok=True)
    workspace = WORKSPACES_DIR / task_id / "repo"

    try:
        token = installation_token(task["installation_id"])
        askpass = write_askpass(attempt_dir)
        env = os.environ.copy()
        env["GIT_ASKPASS"] = str(askpass)
        env["GIT_TERMINAL_PROMPT"] = "0"
        env["COVEN_GIT_TOKEN"] = token
        env["COVEN_CODE_PROVIDER"] = "codex"
        env["COVEN_CODE_HOSTED_REVIEW"] = "1"
        env["HOME"] = str(CODEX_TOKENS_PATH.parent.parent)
        codex_access_token = load_codex_access_token()
        if not codex_access_token:
            return fail_task(
                path,
                task,
                "codex_auth_missing",
                "Missing Codex access token at {}".format(CODEX_TOKENS_PATH),
            )
        env["OPENAI_API_KEY"] = codex_access_token

        if not workspace.exists():
            clone = run_command(
                [
                    "git",
                    "clone",
                    "--depth",
                    "1",
                    "--branch",
                    task["default_branch"],
                    task["clone_url"],
                    str(workspace),
                ],
                env=env,
                timeout=180,
            )
            write_json_atomic(attempt_dir / "clone.json", redacted_command_result(clone))
            if clone["returncode"] != 0:
                return fail_task(path, task, "clone_failed", clone["stderr"])

        review_context = prepare_review_context(task, workspace, token, env, attempt_dir)
        if review_context:
            review_context_path = attempt_dir / "review-context.json"
            write_json_atomic(review_context_path, review_context)
            task["review_context_path"] = str(review_context_path)
            task["review_context_sha256"] = file_sha256(review_context_path)
            task["review_evidence"] = review_evidence(review_context, review_context_path, task)
            write_json_atomic(path, task)

        if not command_exists(COVEN_CODE_BIN):
            return fail_task(
                path,
                task,
                "runtime_missing",
                "COVEN_CODE_BIN is not available on the host: {}".format(COVEN_CODE_BIN),
            )

        cycle_result = run_coven_code_cycle(task, workspace, review_context, attempt_dir, env, 0)
        brief_path = cycle_result["brief_path"]
        result_path = cycle_result["result_path"]
        run = cycle_result["run"]
        task["session_brief_path"] = str(brief_path)
        task["session_brief_sha256"] = file_sha256(brief_path)
        task["runtime_exit_code"] = run["returncode"]
        task["result_path"] = str(result_path)
        write_json_atomic(path, task)

        if cycle_result["result"] is None:
            return fail_task(
                path,
                task,
                "result_missing",
                "coven-code exited {} without writing result.json: {}".format(
                    run["returncode"], run["stderr"]
                ),
            )

        final_cycle = cycle_result
        loop_records = []
        for iteration in range(1, MAX_REVIEW_FIX_LOOPS + 1):
            findings = review_findings(final_cycle["result"])
            if not findings:
                break
            instruction = review_fix_instruction(findings, iteration, MAX_REVIEW_FIX_LOOPS)
            repair_task = task_with_repair_request(task, instruction)
            repair_cycle = run_coven_code_cycle(
                repair_task,
                workspace,
                review_context,
                attempt_dir,
                env,
                iteration,
                instruction,
            )
            remaining = review_findings(repair_cycle["result"])
            loop_records.append(
                {
                    "iteration": iteration,
                    "input_findings": len(findings),
                    "runtime_exit_code": repair_cycle["run"]["returncode"],
                    "result_path": str(repair_cycle["result_path"]),
                    "result_status": (repair_cycle["result"] or {}).get("status"),
                    "remaining_findings": len(remaining),
                }
            )
            task["review_fix_loops"] = loop_records
            task["runtime_exit_code"] = repair_cycle["run"]["returncode"]
            task["result_path"] = str(repair_cycle["result_path"])
            task["updated_at"] = utc_now()
            write_json_atomic(path, task)

            if repair_cycle["result"] is None:
                return fail_task(
                    path,
                    task,
                    "result_missing",
                    "review repair loop {} exited {} without writing result.json: {}".format(
                        iteration,
                        repair_cycle["run"]["returncode"],
                        repair_cycle["run"]["stderr"],
                    ),
                )
            final_cycle = repair_cycle

        result_path = final_cycle["result_path"]
        run = final_cycle["run"]
        task["runtime_exit_code"] = run["returncode"]
        task["result_path"] = str(result_path)
        task["state"] = "completed" if run["returncode"] in (0, 1, 3) else "failed"
        task["updated_at"] = utc_now()
        publish_result_if_configured(task, result_path, token)
        write_json_atomic(path, task)
        return task
    except Exception as exc:
        return fail_task(path, task, "infra_error", repr(exc))


def command_exists(command):
    probe = run_command(["/bin/sh", "-lc", "command -v {}".format(shell_quote(command))], timeout=10)
    return probe["returncode"] == 0


def shell_quote(value):
    return "'" + str(value).replace("'", "'\"'\"'") + "'"


def pr_number_for_task(task):
    task_data = task.get("task") or {}
    target = task.get("target") or {}
    if target.get("kind") == "pull_request" and target.get("pr_number"):
        return int(target.get("pr_number"))
    value = task_data.get("pr_number")
    if value:
        return int(value)
    return None


def prepare_review_context(task, workspace, token, env, attempt_dir):
    pr_number = pr_number_for_task(task)
    if not pr_number:
        return None

    repo = task.get("repository")
    pr = github_request(
        "GET",
        "https://api.github.com/repos/{}/pulls/{}".format(repo, pr_number),
        token,
    )
    files = github_request(
        "GET",
        "https://api.github.com/repos/{}/pulls/{}/files?per_page=100".format(repo, pr_number),
        token,
    )

    fetch = run_command(
        ["git", "fetch", "--depth", "1", "origin", "pull/{}/head".format(pr_number)],
        cwd=str(workspace),
        env=env,
        timeout=180,
    )
    write_json_atomic(attempt_dir / "fetch-pr.json", redacted_command_result(fetch))
    if fetch["returncode"] != 0:
        return {
            "kind": "pull_request",
            "pr_number": pr_number,
            "fetch_error": fetch["stderr"],
            "metadata": summarize_pr(pr),
            "files": summarize_pr_files(files),
        }

    checkout = run_command(["git", "checkout", "--detach", "FETCH_HEAD"], cwd=str(workspace), env=env)
    write_json_atomic(attempt_dir / "checkout-pr.json", redacted_command_result(checkout))

    head = run_command(["git", "rev-parse", "HEAD"], cwd=str(workspace), env=env)
    status = run_command(["git", "status", "--short", "--branch"], cwd=str(workspace), env=env)
    write_json_atomic(attempt_dir / "workspace-git.json", redacted_command_result({
        "args": ["git evidence"],
        "returncode": 0 if head["returncode"] == 0 and status["returncode"] == 0 else 1,
        "stdout": "HEAD={}\n{}".format(head["stdout"].strip(), status["stdout"].strip()),
        "stderr": head["stderr"] + status["stderr"],
    }))

    return {
        "kind": "pull_request",
        "pr_number": pr_number,
        "metadata": summarize_pr(pr),
        "files": summarize_pr_files(files),
        "checkout": {
            "fetch_returncode": fetch["returncode"],
            "checkout_returncode": checkout["returncode"],
            "workspace_head_sha": head["stdout"].strip(),
            "workspace_status": status["stdout"].strip(),
        },
    }


def summarize_pr(pr):
    return {
        "number": pr.get("number"),
        "title": pr.get("title"),
        "state": pr.get("state"),
        "html_url": pr.get("html_url"),
        "base_ref": (pr.get("base") or {}).get("ref"),
        "base_sha": (pr.get("base") or {}).get("sha"),
        "head_ref": (pr.get("head") or {}).get("ref"),
        "head_sha": (pr.get("head") or {}).get("sha"),
        "merge_commit_sha": pr.get("merge_commit_sha"),
    }


def summarize_pr_files(files):
    summarized = []
    for item in files or []:
        patch = item.get("patch") or ""
        summarized.append(
            {
                "filename": item.get("filename"),
                "status": item.get("status"),
                "additions": item.get("additions"),
                "deletions": item.get("deletions"),
                "changes": item.get("changes"),
                "sha": item.get("sha"),
                "patch": patch[:12000],
                "patch_truncated": len(patch) > 12000,
            }
        )
    return summarized


def review_evidence(review_context, review_context_path, task):
    metadata = review_context.get("metadata") or {}
    files = review_context.get("files") or []
    checkout = review_context.get("checkout") or {}
    return {
        "pr_number": review_context.get("pr_number"),
        "base_ref": metadata.get("base_ref"),
        "base_sha": metadata.get("base_sha"),
        "head_ref": metadata.get("head_ref"),
        "head_sha": metadata.get("head_sha"),
        "workspace_head_sha": checkout.get("workspace_head_sha"),
        "changed_file_count": len(files),
        "changed_files": [f.get("filename") for f in files],
        "review_context_path": str(review_context_path),
        "review_context_sha256": file_sha256(review_context_path),
    }


def file_sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def publish_result_if_configured(task, result_path, token):
    publication = task.get("publication") or {}
    mode = publication.get("mode") or "record_only"
    if mode != "comment":
        task["publication_state"] = "held_for_issue_11_publication_gates"
        return

    result = read_json(result_path, {})
    number = (
        (task.get("task") or {}).get("issue_number")
        or (task.get("task") or {}).get("pr_number")
    )
    if not number:
        task["publication_state"] = "publication_skipped_no_issue_or_pr_number"
        return

    body = publication_comment_body(task, result)
    repo = task.get("repository")
    url = "https://api.github.com/repos/{}/issues/{}/comments".format(repo, int(number))
    try:
        response = github_request("POST", url, token, {"body": body})
        task["publication_state"] = "published_comment"
        task["publication_url"] = response.get("html_url")
        task["publication_comment_id"] = response.get("id")
    except Exception as exc:
        task["publication_state"] = "publication_failed"
        task["publication_error"] = redact_tokenish(repr(exc))


def publication_comment_body(task, result):
    status = result.get("status") or "unknown"
    summary = result.get("summary") or "No summary returned."
    pr_body = result.get("pr_body") or ""
    files_changed = result.get("files_changed") or []
    commits = result.get("commits") or []
    task_id = task.get("task_id") or ""
    evidence = task.get("review_evidence") or {}
    review = result.get("review") or {}

    parts = [
        "## Cody dogfood result",
        "",
        "**Status:** {}".format(status),
        "",
        summary.strip(),
    ]
    if pr_body.strip() and pr_body.strip() != summary.strip():
        parts.extend(["", pr_body.strip()])
    parts.extend(review_fix_loop_lines(task))
    parts.extend(["", "### Evidence"])
    if evidence:
        changed_files = evidence.get("changed_files") or []
        parts.extend(
            [
                "- PR: #{}".format(evidence.get("pr_number")),
                "- Base: `{}` @ `{}`".format(evidence.get("base_ref"), evidence.get("base_sha")),
                "- Head: `{}` @ `{}`".format(evidence.get("head_ref"), evidence.get("head_sha")),
                "- Checked-out workspace HEAD: `{}`".format(evidence.get("workspace_head_sha")),
                "- Changed files supplied to agent: {}".format(evidence.get("changed_file_count")),
                "- Review context SHA-256: `{}`".format(evidence.get("review_context_sha256")),
            ]
        )
        if changed_files:
            parts.append("- Files: {}".format(", ".join("`{}`".format(f) for f in changed_files[:20])))
    else:
        parts.append("- No PR review evidence was captured for this run.")
    parts.extend(structured_review_lines(review))
    parts.extend(
        [
            "",
            "**Files changed:** {}".format(len(files_changed)),
            "**Commits:** {}".format(len(commits)),
            "",
            "_Task `{}`. Publication is enabled on the hosted test adapter only._".format(task_id),
        ]
    )
    return "\n".join(parts)


def review_fix_loop_lines(task):
    loops = task.get("review_fix_loops") or []
    if not loops:
        return []

    lines = ["", "### Review fix loop"]
    for loop in loops:
        lines.append(
            "- Iteration {iteration}: input findings {input_findings}, result `{result_status}`, remaining findings {remaining_findings}.".format(
                iteration=loop.get("iteration"),
                input_findings=loop.get("input_findings"),
                result_status=loop.get("result_status") or "unknown",
                remaining_findings=loop.get("remaining_findings"),
            )
        )
    if loops and loops[-1].get("remaining_findings", 0):
        lines.append(
            "- Loop stopped after {} configured iteration(s); unresolved findings remain.".format(
                len(loops)
            )
        )
    return lines


def structured_review_lines(review):
    if not review:
        return ["", "### Structured review", "- No structured review result was emitted."]

    lines = [
        "",
        "### Structured review",
        "- Mode: `{}`".format(review.get("mode") or "unknown"),
        "- Evidence status: `{}`".format(review.get("evidence_status") or "unknown"),
    ]

    reviewed_files = review.get("reviewed_files") or []
    lines.append("- Reviewed files: {}".format(len(reviewed_files)))
    if reviewed_files:
        lines.append(
            "- Reviewed file list: {}".format(
                ", ".join("`{}`".format(path) for path in reviewed_files[:20])
            )
        )
        if len(reviewed_files) > 20:
            lines.append("- Reviewed file list truncated after 20 entries.")

    supporting_files = review.get("supporting_files") or []
    lines.append("- Supporting files inspected: {}".format(len(supporting_files)))
    if supporting_files:
        lines.append(
            "- Supporting file list: {}".format(
                ", ".join("`{}`".format(path) for path in supporting_files[:20])
            )
        )
        if len(supporting_files) > 20:
            lines.append("- Supporting file list truncated after 20 entries.")

    findings = review.get("findings") or []
    lines.append("- Findings: {}".format(len(findings)))
    for index, finding in enumerate(findings[:10], start=1):
        location = finding.get("file") or "unknown file"
        if finding.get("line") is not None:
            location = "{}:{}".format(location, finding.get("line"))
        lines.append(
            "  {}. `{}` {} - {}".format(
                index,
                finding.get("severity") or "unknown",
                location,
                finding.get("title") or "Untitled finding",
            )
        )
    if len(findings) > 10:
        lines.append("- Findings truncated after 10 entries.")

    no_findings_reason = review.get("no_findings_reason")
    if no_findings_reason:
        lines.append("- No-findings reason: {}".format(no_findings_reason))

    tests_run = review.get("tests_run") or []
    lines.append("- Tests reported by runtime: {}".format(len(tests_run)))
    for test in tests_run[:10]:
        summary = test.get("output_summary")
        suffix = " - {}".format(summary) if summary else ""
        lines.append(
            "  - `{}`: `{}`{}".format(
                test.get("command") or "unknown command",
                test.get("status") or "unknown",
                suffix,
            )
        )
    if len(tests_run) > 10:
        lines.append("- Test list truncated after 10 entries.")

    limitations = review.get("limitations") or []
    lines.append("- Limitations: {}".format(len(limitations)))
    for limitation in limitations[:10]:
        lines.append("  - {}".format(limitation))
    if len(limitations) > 10:
        lines.append("- Limitation list truncated after 10 entries.")

    return lines


def load_codex_access_token():
    for path in codex_token_candidates():
        try:
            data = read_json(path, {})
            token = str(data.get("access_token") or "").strip()
            if token:
                return token
        except Exception:
            continue
    return None


def codex_token_candidates():
    yield CODEX_TOKENS_PATH

    coven_home = CODEX_TOKENS_PATH.parent
    registry = read_json(coven_home / "accounts.json", {})
    active = (
        registry.get("providers", {})
        .get("codex", {})
        .get("active")
    )
    if active:
        yield coven_home / "accounts" / "codex" / str(active) / "codex_tokens.json"

    accounts_root = coven_home / "accounts" / "codex"
    if accounts_root.exists():
        for path in accounts_root.glob("*/codex_tokens.json"):
            yield path


def redacted_command_result(result):
    redacted = dict(result)
    for key in ("stdout", "stderr"):
        redacted[key] = redact_tokenish(redacted.get(key) or "")
    return redacted


def redact_tokenish(text):
    if not text:
        return text
    markers = ["ghs_", "ghu_", "github_pat_", "x-access-token:"]
    redacted = text
    for marker in markers:
        while marker in redacted:
            index = redacted.find(marker)
            end = index + len(marker)
            while end < len(redacted) and redacted[end] not in " \n\r\t'\"":
                end += 1
            redacted = redacted[:index] + marker + "[redacted]" + redacted[end:]
    return redacted


def fail_task(path, task, reason, detail):
    task["state"] = "failed"
    task["failure_category"] = reason
    task["failure_detail"] = redact_tokenish(str(detail))[-4000:]
    task["updated_at"] = utc_now()
    write_json_atomic(path, task)
    return task
