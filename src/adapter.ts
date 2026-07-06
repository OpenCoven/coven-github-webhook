import {createHash, createHmac, createSign, randomUUID} from "node:crypto";
import {existsSync, mkdirSync, readdirSync, readFileSync, renameSync, rmSync, writeFileSync} from "node:fs";
import {homedir} from "node:os";
import {basename, dirname, join, resolve} from "node:path";
import {spawnSync} from "node:child_process";

export type JsonValue = null | boolean | number | string | JsonValue[] | JsonObject;
export type JsonObject = {[key: string]: JsonValue | undefined};

export interface AdapterConfig {
  rootDir: string;
  stateDir: string;
  deliveriesDir: string;
  tasksDir: string;
  workspacesDir: string;
  attemptsDir: string;
  policyPath: string;
  privateKeyPath: string;
  appId: string;
  webhookSecret: string;
  covenCodeBin: string;
  covenCodeModel: string;
  maxReviewFixLoops: number;
  codexTokensPath: string;
  maxWebhookBodyBytes: number;
}

export interface AdapterRequest {
  method: string;
  path: string;
  headers: Map<string, string>;
  rawBody: Buffer;
}

export interface AdapterResponse {
  status: number;
  body: JsonObject;
}

interface CommandResult extends JsonObject {
  args: string[];
  returncode: number;
  stdout: string;
  stderr: string;
}

interface CycleResult {
  cycle: number;
  brief_path: string;
  result_path: string;
  run_path: string;
  run: CommandResult;
  result: JsonObject | null;
}

const DEFAULT_POLICY: JsonObject = {
  version: 1,
  installations: {},
};

const MAX_WEBHOOK_BODY_BYTES = 10 * 1024 * 1024;

export function createConfig(env: NodeJS.ProcessEnv = process.env, rootDir = process.cwd()): AdapterConfig {
  const stateDir = resolve(env.COVEN_GITHUB_STATE_DIR || join(rootDir, "coven-github-state"));
  const config: AdapterConfig = {
    rootDir,
    stateDir,
    deliveriesDir: join(stateDir, "deliveries"),
    tasksDir: join(stateDir, "tasks"),
    workspacesDir: join(stateDir, "workspaces"),
    attemptsDir: join(stateDir, "attempts"),
    policyPath: resolve(env.COVEN_GITHUB_POLICY_PATH || join(rootDir, "coven-github-policy.json")),
    privateKeyPath: resolve(env.GITHUB_APP_PRIVATE_KEY_PATH || join(rootDir, ".coven-github-private-key.pem")),
    appId: (env.GITHUB_APP_ID || "").trim(),
    webhookSecret: (env.GITHUB_WEBHOOK_SECRET || env.WEBHOOK_SECRET || "").trim(),
    covenCodeBin: (env.COVEN_CODE_BIN || "coven-code").trim() || "coven-code",
    covenCodeModel: (env.COVEN_CODE_MODEL || "gpt-5.5").trim(),
    maxReviewFixLoops: envInt(env.COVEN_REVIEW_FIX_LOOPS, 0, 0, 5),
    codexTokensPath: configuredCodexTokensPath(env),
    maxWebhookBodyBytes: MAX_WEBHOOK_BODY_BYTES,
  };

  for (const directory of [config.deliveriesDir, config.tasksDir, config.workspacesDir, config.attemptsDir]) {
    mkdirSync(directory, {recursive: true});
  }
  return config;
}

function envInt(raw: string | undefined, fallback: number, minimum: number, maximum: number): number {
  const parsed = Number.parseInt((raw || "").trim(), 10);
  if (!Number.isFinite(parsed)) {
    return fallback;
  }
  return Math.max(minimum, Math.min(maximum, parsed));
}

function configuredCodexTokensPath(env: NodeJS.ProcessEnv): string {
  const configured = (env.COVEN_CODE_CODEX_TOKENS_PATH || "").trim();
  if (configured) {
    return resolve(configured.replace(/^~/, homedir()));
  }
  return join(homedir(), ".coven-code", "codex_tokens.json");
}

function utcNow(): string {
  return new Date().toISOString();
}

function readJson<T extends JsonValue>(path: string, fallback: T): T {
  try {
    return JSON.parse(readFileSync(path, "utf8")) as T;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      return fallback;
    }
    throw error;
  }
}

function writeJsonAtomic(path: string, value: JsonValue): void {
  mkdirSync(dirname(path), {recursive: true});
  const tmpName = join(dirname(path), `${basename(path)}.${randomUUID()}.tmp`);
  try {
    writeFileSync(tmpName, `${stableStringify(value)}\n`, "utf8");
    renameSync(tmpName, path);
  } finally {
    if (existsSync(tmpName)) {
      rmSync(tmpName);
    }
  }
}

function stableStringify(value: JsonValue, indent = 0): string {
  const space = "  ".repeat(indent);
  const nextSpace = "  ".repeat(indent + 1);
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    if (value.length === 0) {
      return "[]";
    }
    return `[\n${value.map((item) => `${nextSpace}${stableStringify(item, indent + 1)}`).join(",\n")}\n${space}]`;
  }
  const entries = Object.entries(value)
    .filter(([, item]) => item !== undefined)
    .sort(([left], [right]) => left.localeCompare(right));
  if (entries.length === 0) {
    return "{}";
  }
  return `{\n${entries
    .map(([key, item]) => `${nextSpace}${JSON.stringify(key)}: ${stableStringify(item as JsonValue, indent + 1)}`)
    .join(",\n")}\n${space}}`;
}

function stableCompactStringify(value: JsonValue): string {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => stableCompactStringify(item)).join(",")}]`;
  }
  return `{${Object.entries(value)
    .filter(([, item]) => item !== undefined)
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([key, item]) => `${JSON.stringify(key)}:${stableCompactStringify(item as JsonValue)}`)
    .join(",")}}`;
}

function b64url(raw: Buffer | string): string {
  return Buffer.from(raw).toString("base64url");
}

function githubAppJwt(config: AdapterConfig): string {
  if (!config.appId) {
    throw new Error("GITHUB_APP_ID is required");
  }
  const now = Math.floor(Date.now() / 1000);
  const header = {alg: "RS256", typ: "JWT"};
  const payload = {iat: now - 60, exp: now + 540, iss: config.appId};
  const signingInput = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(payload))}`;
  const privateKey = readFileSync(config.privateKeyPath, "utf8");
  const signature = createSign("RSA-SHA256").update(signingInput).sign(privateKey);
  return `${signingInput}.${b64url(signature)}`;
}

async function githubRequest(
  method: string,
  url: string,
  token: string,
  body?: JsonObject,
): Promise<JsonValue> {
  const response = await fetch(url, {
    method,
    headers: {
      Accept: "application/vnd.github+json",
      Authorization: `Bearer ${token}`,
      "User-Agent": "coven-github-hosted-prototype",
      "X-GitHub-Api-Version": "2022-11-28",
      ...(body === undefined ? {} : {"Content-Type": "application/json"}),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const raw = await response.text();
  if (!response.ok) {
    throw new Error(`GitHub API ${method} ${url} failed: ${raw}`);
  }
  return raw ? (JSON.parse(raw) as JsonValue) : {};
}

async function installationToken(config: AdapterConfig, installationId: JsonValue | undefined): Promise<string> {
  const response = (await githubRequest(
    "POST",
    `https://api.github.com/app/installations/${installationId}/access_tokens`,
    githubAppJwt(config),
    {},
  )) as JsonObject;
  const token = response.token;
  if (typeof token !== "string" || !token) {
    throw new Error("GitHub installation token response did not include token");
  }
  return token;
}

function loadPolicy(config: AdapterConfig): JsonObject {
  if (!existsSync(config.policyPath)) {
    writeJsonAtomic(config.policyPath, DEFAULT_POLICY);
  }
  return readJson(config.policyPath, DEFAULT_POLICY);
}

function repoPolicy(config: AdapterConfig, payload: JsonObject): [string, string, JsonObject | undefined] {
  const policy = loadPolicy(config);
  const installationId = String(((payload.installation as JsonObject | undefined)?.id as JsonValue) || "");
  const repository = (payload.repository as JsonObject | undefined) || {};
  const repoId = String((repository.id as JsonValue) || "");
  const installation = (((policy.installations as JsonObject | undefined) || {})[installationId] as JsonObject | undefined) || {};
  const repo = ((installation.repositories as JsonObject | undefined) || {})[repoId] as JsonObject | undefined;
  return [installationId, repoId, repo];
}

function deliveryPath(config: AdapterConfig, deliveryId: string): string {
  return join(config.deliveriesDir, `${deliveryId}.json`);
}

function taskPath(config: AdapterConfig, taskId: string): string {
  return join(config.tasksDir, `${taskId}.json`);
}

function header(headers: Map<string, string>, name: string): string {
  return headers.get(name.toLowerCase()) || "";
}

function bodyFromContentLength(request: AdapterRequest, maxBytes: number): Buffer | "too_large" {
  const rawLength = (header(request.headers, "Content-Length") || "").trim();
  const parsed = rawLength && /^-?\d+$/.test(rawLength) ? Number.parseInt(rawLength, 10) : -1;
  const length = Number.isFinite(parsed) ? parsed : -1;
  if (length > maxBytes) {
    return "too_large";
  }
  if (length >= 0) {
    return request.rawBody.subarray(0, length);
  }
  if (request.rawBody.length > maxBytes) {
    return "too_large";
  }
  return request.rawBody;
}

export function verifyWebhookSignature(
  secret: string,
  body: Buffer,
  signatureHeader: string,
): [boolean, string | undefined] {
  if (!secret) {
    return [false, "webhook secret not configured"];
  }
  if (!signatureHeader) {
    return [false, "missing signature"];
  }
  const signature = signatureHeader.trim();
  const prefix = "sha256=";
  if (!signature.startsWith(prefix)) {
    return [false, "invalid signature"];
  }
  const expected = `${prefix}${createHmac("sha256", secret).update(body).digest("hex")}`;
  if (!constantTimeEqual(expected, signature)) {
    return [false, "invalid signature"];
  }
  return [true, undefined];
}

function constantTimeEqual(left: string, right: string): boolean {
  const leftBuffer = Buffer.from(left);
  const rightBuffer = Buffer.from(right);
  if (leftBuffer.length !== rightBuffer.length) {
    return false;
  }
  return timingSafeCompare(leftBuffer, rightBuffer);
}

function timingSafeCompare(left: Buffer, right: Buffer): boolean {
  let result = 0;
  for (let index = 0; index < left.length; index += 1) {
    result |= left[index] ^ right[index];
  }
  return result === 0;
}

export async function handleRequest(
  config: AdapterConfig,
  request: AdapterRequest,
  debug: (message: string) => void = (message) => console.log(message),
): Promise<AdapterResponse> {
  const method = request.method.toUpperCase();
  if (method === "GET" && (request.path === "/" || request.path === "/healthz")) {
    return {status: 200, body: {ok: true}};
  }
  if (method !== "POST" || (request.path !== "/" && request.path !== "/webhook")) {
    return {status: 404, body: {error: "not found"}};
  }

  const body = bodyFromContentLength(request, config.maxWebhookBodyBytes);
  if (body === "too_large") {
    return {status: 413, body: {error: "payload too large"}};
  }

  const [ok, error] = verifyWebhookSignature(config.webhookSecret, body, header(request.headers, "X-Hub-Signature-256"));
  if (!ok) {
    return {
      status: error === "webhook secret not configured" ? 500 : 401,
      body: {error},
    };
  }

  const eventName = header(request.headers, "X-GitHub-Event");
  if (!eventName) {
    return {status: 400, body: {error: "missing event"}};
  }

  let payload: JsonObject;
  try {
    payload = JSON.parse(body.toString("utf8")) as JsonObject;
  } catch {
    return {status: 400, body: {error: "invalid json"}};
  }

  const deliveryId = header(request.headers, "X-GitHub-Delivery") || randomUUID();
  return {
    status: 200,
    body: await routeDelivery(config, eventName, deliveryId, payload, debug),
  };
}

function payloadHash(payload: JsonObject): string {
  return sha256(stableCompactStringify(payload));
}

function sha256(raw: string | Buffer): string {
  return createHash("sha256").update(raw).digest("hex");
}

function deliveryRecord(deliveryId: string, eventName: string, payload: JsonObject): JsonObject {
  const repository = (payload.repository as JsonObject | undefined) || {};
  const installation = (payload.installation as JsonObject | undefined) || {};
  return {
    delivery_id: deliveryId,
    event: eventName,
    action: payload.action,
    installation_id: installation.id,
    repository_id: repository.id,
    repository: repository.full_name,
    payload_hash: payloadHash(payload),
    received_at: utcNow(),
    state: "received",
    issue_refs: ["OpenCoven/coven-github#2"],
  };
}

function mentioned(text: JsonValue | undefined, policy: JsonObject): boolean {
  const normalized = String(text || "").toLowerCase();
  for (const username of ((policy.bot_usernames as JsonValue[]) || [])) {
    if (normalized.includes(`@${String(username).toLowerCase()}`)) {
      return true;
    }
  }
  return false;
}

function labelsIncludeTrigger(labels: JsonValue | undefined, policy: JsonObject): boolean {
  const wanted = new Set(((policy.trigger_labels as JsonValue[]) || []).map((label) => String(label)));
  for (const label of (Array.isArray(labels) ? labels : [])) {
    const name = typeof label === "object" && label !== null && !Array.isArray(label)
      ? String((label as JsonObject).name || "").trim()
      : String(label).trim();
    if (wanted.has(name)) {
      return true;
    }
  }
  return false;
}

export function buildTaskFromEvent(
  eventName: string,
  deliveryId: string,
  payload: JsonObject,
  policy: JsonObject,
): JsonObject {
  const repository = (payload.repository as JsonObject | undefined) || {};
  const installation = (payload.installation as JsonObject | undefined) || {};
  const familiar = policy.familiar;
  const fullName = String(repository.full_name || "");
  const base: JsonObject = {
    task_id: deliveryId,
    delivery_id: deliveryId,
    created_at: utcNow(),
    updated_at: utcNow(),
    state: "queued",
    attempts: 0,
    installation_id: installation.id,
    repository_id: repository.id,
    repository: repository.full_name,
    clone_url: repository.clone_url || `https://github.com/${fullName}.git`,
    default_branch: repository.default_branch || policy.default_branch || "main",
    familiar,
    publication: policy.publication || {mode: "record_only"},
    issue_refs: ["OpenCoven/coven-github#2", "OpenCoven/coven-github#7"],
  };
  if (!familiar) {
    return ignored(base, "missing_familiar_policy");
  }

  if (eventName === "issue_comment") {
    const issue = (payload.issue as JsonObject | undefined) || {};
    const comment = (payload.comment as JsonObject | undefined) || {};
    if (!mentioned(comment.body, policy)) {
      return ignored(base, "issue_comment_without_mention");
    }
    if (issue.pull_request) {
      Object.assign(base, {
        trigger: "pr_mention",
        target: {kind: "pull_request", pr_number: Number(issue.number || 0)},
        task: {
          kind: "respond_to_mention",
          issue_number: Number(issue.number || 0),
          comment_body: comment.body || "",
        },
        issue_refs: [...((base.issue_refs as JsonValue[]) || []), "OpenCoven/coven-github#4"],
      });
      return base;
    }
    Object.assign(base, {
      trigger: "issue_mention",
      task: {
        kind: "respond_to_mention",
        issue_number: Number(issue.number || 0),
        comment_body: comment.body || "",
      },
      issue_refs: [...((base.issue_refs as JsonValue[]) || []), "OpenCoven/coven-github#4"],
    });
    return base;
  }

  if (eventName === "pull_request_review_comment") {
    const comment = (payload.comment as JsonObject | undefined) || {};
    const pullRequest = (payload.pull_request as JsonObject | undefined) || {};
    if (!mentioned(comment.body, policy)) {
      return ignored(base, "pr_review_comment_without_mention");
    }
    Object.assign(base, {
      trigger: "pr_review_comment",
      task: {
        kind: "address_review_comment",
        pr_number: Number(pullRequest.number || 0),
        comment_body: comment.body || "",
        diff_hunk: comment.diff_hunk,
        path: comment.path,
        line: comment.line,
        side: comment.side,
        commit_id: comment.commit_id,
        html_url: comment.html_url,
      },
      issue_refs: [...((base.issue_refs as JsonValue[]) || []), "OpenCoven/coven-github#4"],
    });
    return base;
  }

  if (eventName === "issues") {
    const issue = (payload.issue as JsonObject | undefined) || {};
    const action = payload.action;
    if (action !== "assigned" && action !== "labeled" && action !== "opened") {
      return ignored(base, "unsupported_issue_action");
    }
    if (action === "labeled" && !labelsIncludeTrigger(issue.labels, policy)) {
      return ignored(base, "issue_label_not_enabled");
    }
    Object.assign(base, {
      trigger: action === "assigned" ? "issue_assigned" : "issue_mention",
      task: {
        kind: "fix_issue",
        issue_number: Number(issue.number || 0),
        issue_title: issue.title || "",
        issue_body: issue.body || "",
      },
      issue_refs: [...((base.issue_refs as JsonValue[]) || []), "OpenCoven/coven-github#4"],
    });
    return base;
  }

  if (eventName === "pull_request") {
    const pullRequest = (payload.pull_request as JsonObject | undefined) || {};
    const head = (pullRequest.head as JsonObject | undefined) || {};
    const baseRef = (pullRequest.base as JsonObject | undefined) || {};
    Object.assign(base, {
      state: "ignored",
      ignored_reason: "pull_request_review_task_not_in_headless_contract_v1",
      trigger: "pull_request",
      target: {
        action: payload.action,
        number: pullRequest.number,
        head_sha: head.sha,
        head_ref: head.ref,
        base_ref: baseRef.ref,
      },
      issue_refs: [...((base.issue_refs as JsonValue[]) || []), "OpenCoven/coven-github#10"],
    });
    return base;
  }

  if (eventName === "push") {
    Object.assign(base, {
      state: "ignored",
      ignored_reason: "push_review_task_not_in_headless_contract_v1",
      trigger: "push",
      target: {
        ref: payload.ref,
        before: payload.before,
        after: payload.after,
        commit_count: Array.isArray(payload.commits) ? payload.commits.length : 0,
      },
      issue_refs: [...((base.issue_refs as JsonValue[]) || []), "OpenCoven/coven-github#10"],
    });
    return base;
  }

  return ignored(base, "unsupported_event");
}

function ignored(base: JsonObject, reason: string): JsonObject {
  base.state = "ignored";
  base.ignored_reason = reason;
  return base;
}

async function routeDelivery(
  config: AdapterConfig,
  eventName: string,
  deliveryId: string,
  payload: JsonObject,
  debug: (message: string) => void,
): Promise<JsonObject> {
  const deliveryFile = deliveryPath(config, deliveryId);
  if (existsSync(deliveryFile)) {
    const existing = readJson<JsonObject>(deliveryFile, {});
    return {
      ok: true,
      action: "duplicate_ignored",
      delivery_id: deliveryId,
      task_id: existing.task_id,
      state: existing.state,
    };
  }

  const delivery = deliveryRecord(deliveryId, eventName, payload);
  const [installationId, repoId, policy] = repoPolicy(config, payload);
  if (!policy) {
    delivery.state = "ignored";
    delivery.routing_result = "no_policy_for_installation_repo";
    delivery.installation_id = installationId || delivery.installation_id;
    delivery.repository_id = repoId || delivery.repository_id;
    writeJsonAtomic(deliveryFile, delivery);
    return {
      ok: true,
      action: "ignored",
      delivery_id: deliveryId,
      reason: "no_policy_for_installation_repo",
    };
  }

  const task = buildTaskFromEvent(eventName, deliveryId, payload, policy);
  task.policy_snapshot = {
    enabled_triggers: policy.enabled_triggers || [],
    publication: policy.publication || {mode: "record_only"},
  };
  writeJsonAtomic(taskPath(config, String(task.task_id)), task);

  delivery.task_id = task.task_id;
  delivery.state = task.state;
  delivery.routing_result = task.ignored_reason || "queued";
  writeJsonAtomic(deliveryFile, delivery);

  if (task.state === "queued") {
    try {
      await runTask(config, String(task.task_id));
    } catch (error) {
      debug(`COVEN GITHUB TASK RUN FAIL task_id=${task.task_id} ${String((error as Error).stack || error)}`);
    }
  }

  return {
    ok: true,
    action: task.state !== "ignored" ? "accepted" : "ignored",
    delivery_id: deliveryId,
    task_id: task.task_id,
    state: readJson<JsonObject>(taskPath(config, String(task.task_id)), task).state,
    reason: task.ignored_reason,
    queued: task.state === "queued",
  };
}

function runCommand(args: string[], cwd?: string, env?: NodeJS.ProcessEnv, timeoutSeconds = 300): CommandResult {
  const proc = spawnSync(args[0], args.slice(1), {
    cwd,
    env,
    encoding: "utf8",
    timeout: timeoutSeconds * 1000,
    maxBuffer: 20 * 1024 * 1024,
  });
  return {
    args,
    returncode: proc.status ?? 1,
    stdout: String(proc.stdout || "").slice(-8000),
    stderr: `${String(proc.stderr || "")}${proc.error ? String(proc.error.message || proc.error) : ""}`.slice(-8000),
  };
}

function writeAskpass(workDir: string): string {
  const script = join(workDir, "git-askpass.sh");
  writeFileSync(script, "#!/bin/sh\nprintf '%s\\n' \"$COVEN_GIT_TOKEN\"\n", {encoding: "utf8", mode: 0o700});
  return script;
}

function sessionBrief(
  task: JsonObject,
  workspace: string,
  reviewContext?: JsonObject | null,
  extraAuditInstruction?: string,
): JsonObject {
  const [owner, name] = String(task.repository || "/").split("/", 2);
  const brief: JsonObject = {
    contract_version: "2",
    trigger: task.trigger,
    repo: {
      owner,
      name,
      clone_url: task.clone_url,
      default_branch: task.default_branch,
    },
    task: task.task,
    familiar: task.familiar,
    workspace: {root: workspace},
  };
  if (reviewContext) {
    brief.review_context = reviewContext;
    let instruction = "This run is evidence-backed. Review the supplied PR metadata and changed-file patches in review_context before responding. Cite the specific changed files you inspected in the result summary.";
    if (extraAuditInstruction) {
      instruction = `${instruction}\n\n${extraAuditInstruction}`;
    }
    brief.audit_instruction = instruction;
  }
  return brief;
}

function runCovenCodeCycle(
  config: AdapterConfig,
  task: JsonObject,
  workspace: string,
  reviewContext: JsonObject | null | undefined,
  attemptDir: string,
  env: NodeJS.ProcessEnv,
  cycle: number,
  extraAuditInstruction?: string,
): CycleResult {
  const suffix = cycle === 0 ? "" : `-repair-${cycle}`;
  const briefPath = join(attemptDir, `session-brief${suffix}.json`);
  const resultPath = join(attemptDir, `result${suffix}.json`);
  const runPath = join(attemptDir, `run${suffix}.json`);

  writeJsonAtomic(briefPath, sessionBrief(task, workspace, reviewContext, extraAuditInstruction));
  const run = runCommand(
    [
      config.covenCodeBin,
      "--headless",
      "--hosted-review",
      "--provider",
      "codex",
      "--model",
      config.covenCodeModel,
      "--context",
      briefPath,
      "--output",
      resultPath,
    ],
    workspace,
    env,
    1800,
  );
  writeJsonAtomic(runPath, redactedCommandResult(run));
  return {
    cycle,
    brief_path: briefPath,
    result_path: resultPath,
    run_path: runPath,
    run,
    result: existsSync(resultPath) ? readJson<JsonObject | null>(resultPath, null) : null,
  };
}

function reviewFindings(result: JsonObject | null | undefined): JsonObject[] {
  if (!result) {
    return [];
  }
  const review = (result.review as JsonObject | undefined) || {};
  const mode = review.mode;
  if (mode !== "pull_request" && mode !== "review_comment") {
    return [];
  }
  return Array.isArray(review.findings) ? (review.findings as JsonObject[]) : [];
}

function reviewFixInstruction(findings: JsonObject[], iteration: number, maxIterations: number): string {
  const lines = [
    `Autofix review loop iteration ${iteration}/${maxIterations}.`,
    "The previous hosted review returned structured findings. Fix the findings below, run the relevant checks you can run safely, then perform another bounded review of the updated code using the required review sections.",
    "If a finding cannot be fixed safely, leave a clear limitation and explain the remaining blocker. Do not merely restate the findings.",
    "",
    "Findings to fix:",
  ];
  findings.slice(0, 10).forEach((finding, index) => {
    let location = String(finding.file || "unknown file");
    if (finding.line !== undefined && finding.line !== null) {
      location = `${location}:${finding.line}`;
    }
    lines.push(`${index + 1}. [${finding.severity || "unknown"}] \`${location}\` ${finding.title || "Untitled finding"}`);
    const body = String(finding.body || "").trim();
    if (body) {
      lines.push(`   Body: ${body.slice(0, 1200)}`);
    }
    const recommendation = String(finding.recommendation || "").trim();
    if (recommendation) {
      lines.push(`   Recommendation: ${recommendation.slice(0, 1200)}`);
    }
  });
  if (findings.length > 10) {
    lines.push("Only the first 10 findings are listed; inspect the prior result for the full set.");
  }
  return lines.join("\n");
}

function taskWithRepairRequest(task: JsonObject, instruction: string): JsonObject {
  const copy = JSON.parse(JSON.stringify(task)) as JsonObject;
  const taskData = ((copy.task as JsonObject | undefined) || {}) as JsonObject;
  const explicitRequest = `\n\nPlease fix the review findings from the previous hosted review cycle. After fixing them, rerun relevant checks and produce another structured review.\n\n${instruction}`;
  if ("comment_body" in taskData) {
    taskData.comment_body = String(taskData.comment_body || "") + explicitRequest;
  } else if ("issue_body" in taskData) {
    taskData.issue_body = String(taskData.issue_body || "") + explicitRequest;
  }
  copy.task = taskData;
  return copy;
}

async function runTask(config: AdapterConfig, taskId: string): Promise<JsonObject> {
  const path = taskPath(config, taskId);
  const task = readJson<JsonObject>(path, {});
  if (task.state !== "queued") {
    return task;
  }

  task.state = "running";
  task.attempts = Number(task.attempts || 0) + 1;
  task.updated_at = utcNow();
  writeJsonAtomic(path, task);

  const attemptDir = join(config.attemptsDir, taskId, String(task.attempts));
  mkdirSync(attemptDir, {recursive: true});
  const workspace = join(config.workspacesDir, taskId, "repo");

  try {
    const token = await installationToken(config, task.installation_id);
    const askpass = writeAskpass(attemptDir);
    const env: NodeJS.ProcessEnv = {
      ...process.env,
      GIT_ASKPASS: askpass,
      GIT_TERMINAL_PROMPT: "0",
      COVEN_GIT_TOKEN: token,
      COVEN_CODE_PROVIDER: "codex",
      COVEN_CODE_HOSTED_REVIEW: "1",
      HOME: dirname(dirname(config.codexTokensPath)),
    };
    const codexAccessToken = loadCodexAccessToken(config);
    if (!codexAccessToken) {
      return failTask(path, task, "codex_auth_missing", `Missing Codex access token at ${config.codexTokensPath}`);
    }
    env.OPENAI_API_KEY = codexAccessToken;

    if (!existsSync(workspace)) {
      const clone = runCommand(
        ["git", "clone", "--depth", "1", "--branch", String(task.default_branch), String(task.clone_url), workspace],
        undefined,
        env,
        180,
      );
      writeJsonAtomic(join(attemptDir, "clone.json"), redactedCommandResult(clone));
      if (clone.returncode !== 0) {
        return failTask(path, task, "clone_failed", clone.stderr);
      }
    }

    const reviewContext = await prepareReviewContext(config, task, workspace, token, env, attemptDir);
    if (reviewContext) {
      const reviewContextPath = join(attemptDir, "review-context.json");
      writeJsonAtomic(reviewContextPath, reviewContext);
      task.review_context_path = reviewContextPath;
      task.review_context_sha256 = fileSha256(reviewContextPath);
      task.review_evidence = reviewEvidence(reviewContext, reviewContextPath, task);
      writeJsonAtomic(path, task);
    }

    if (!commandExists(config.covenCodeBin)) {
      return failTask(path, task, "runtime_missing", `COVEN_CODE_BIN is not available on the host: ${config.covenCodeBin}`);
    }

    const firstCycle = runCovenCodeCycle(config, task, workspace, reviewContext, attemptDir, env, 0);
    task.session_brief_path = firstCycle.brief_path;
    task.session_brief_sha256 = fileSha256(String(firstCycle.brief_path));
    task.runtime_exit_code = firstCycle.run.returncode;
    task.result_path = firstCycle.result_path;
    writeJsonAtomic(path, task);

    if (!firstCycle.result) {
      return failTask(path, task, "result_missing", `coven-code exited ${firstCycle.run.returncode} without writing result.json: ${firstCycle.run.stderr}`);
    }

    let finalCycle = firstCycle;
    const loopRecords: JsonObject[] = [];
    for (let iteration = 1; iteration <= config.maxReviewFixLoops; iteration += 1) {
      const findings = reviewFindings(finalCycle.result as JsonObject);
      if (!findings.length) {
        break;
      }
      const instruction = reviewFixInstruction(findings, iteration, config.maxReviewFixLoops);
      const repairTask = taskWithRepairRequest(task, instruction);
      const repairCycle = runCovenCodeCycle(config, repairTask, workspace, reviewContext, attemptDir, env, iteration, instruction);
      const remaining = reviewFindings(repairCycle.result as JsonObject);
      loopRecords.push({
        iteration,
        input_findings: findings.length,
        runtime_exit_code: repairCycle.run.returncode,
        result_path: repairCycle.result_path,
        result_status: ((repairCycle.result as JsonObject | null)?.status as JsonValue) || undefined,
        remaining_findings: remaining.length,
      });
      task.review_fix_loops = loopRecords;
      task.runtime_exit_code = repairCycle.run.returncode;
      task.result_path = repairCycle.result_path;
      task.updated_at = utcNow();
      writeJsonAtomic(path, task);

      if (!repairCycle.result) {
        return failTask(path, task, "result_missing", `review repair loop ${iteration} exited ${repairCycle.run.returncode} without writing result.json: ${repairCycle.run.stderr}`);
      }
      finalCycle = repairCycle;
    }

    task.runtime_exit_code = finalCycle.run.returncode;
    task.result_path = finalCycle.result_path;
    task.state = [0, 1, 3].includes(finalCycle.run.returncode) ? "completed" : "failed";
    task.updated_at = utcNow();
    await publishResultIfConfigured(task, String(finalCycle.result_path), token);
    writeJsonAtomic(path, task);
    return task;
  } catch (error) {
    return failTask(path, task, "infra_error", String((error as Error).stack || error));
  }
}

function commandExists(command: string): boolean {
  return runCommand(["/bin/sh", "-lc", `command -v ${shellQuote(command)}`], undefined, undefined, 10).returncode === 0;
}

function shellQuote(value: string): string {
  return `'${String(value).replaceAll("'", "'\"'\"'")}'`;
}

function prNumberForTask(task: JsonObject): number | null {
  const taskData = (task.task as JsonObject | undefined) || {};
  const target = (task.target as JsonObject | undefined) || {};
  if (target.kind === "pull_request" && target.pr_number) {
    return Number(target.pr_number);
  }
  if (taskData.pr_number) {
    return Number(taskData.pr_number);
  }
  return null;
}

async function prepareReviewContext(
  config: AdapterConfig,
  task: JsonObject,
  workspace: string,
  token: string,
  env: NodeJS.ProcessEnv,
  attemptDir: string,
): Promise<JsonObject | null> {
  const prNumber = prNumberForTask(task);
  if (!prNumber) {
    return null;
  }

  const repo = String(task.repository);
  const pr = (await githubRequest("GET", `https://api.github.com/repos/${repo}/pulls/${prNumber}`, token)) as JsonObject;
  const files = (await githubRequest("GET", `https://api.github.com/repos/${repo}/pulls/${prNumber}/files?per_page=100`, token)) as JsonObject[];

  const fetch = runCommand(["git", "fetch", "--depth", "1", "origin", `pull/${prNumber}/head`], workspace, env, 180);
  writeJsonAtomic(join(attemptDir, "fetch-pr.json"), redactedCommandResult(fetch));
  if (fetch.returncode !== 0) {
    return {
      kind: "pull_request",
      pr_number: prNumber,
      fetch_error: fetch.stderr,
      metadata: summarizePr(pr),
      files: summarizePrFiles(files),
    };
  }

  const checkout = runCommand(["git", "checkout", "--detach", "FETCH_HEAD"], workspace, env);
  writeJsonAtomic(join(attemptDir, "checkout-pr.json"), redactedCommandResult(checkout));
  const head = runCommand(["git", "rev-parse", "HEAD"], workspace, env);
  const status = runCommand(["git", "status", "--short", "--branch"], workspace, env);
  writeJsonAtomic(join(attemptDir, "workspace-git.json"), redactedCommandResult({
    args: ["git evidence"],
    returncode: head.returncode === 0 && status.returncode === 0 ? 0 : 1,
    stdout: `HEAD=${head.stdout.trim()}\n${status.stdout.trim()}`,
    stderr: head.stderr + status.stderr,
  }));

  return {
    kind: "pull_request",
    pr_number: prNumber,
    metadata: summarizePr(pr),
    files: summarizePrFiles(files),
    checkout: {
      fetch_returncode: fetch.returncode,
      checkout_returncode: checkout.returncode,
      workspace_head_sha: head.stdout.trim(),
      workspace_status: status.stdout.trim(),
    },
  };
}

function summarizePr(pr: JsonObject): JsonObject {
  const base = (pr.base as JsonObject | undefined) || {};
  const head = (pr.head as JsonObject | undefined) || {};
  return {
    number: pr.number,
    title: pr.title,
    state: pr.state,
    html_url: pr.html_url,
    base_ref: base.ref,
    base_sha: base.sha,
    head_ref: head.ref,
    head_sha: head.sha,
    merge_commit_sha: pr.merge_commit_sha,
  };
}

function summarizePrFiles(files: JsonObject[]): JsonObject[] {
  return (files || []).map((item) => {
    const patch = String(item.patch || "");
    return {
      filename: item.filename,
      status: item.status,
      additions: item.additions,
      deletions: item.deletions,
      changes: item.changes,
      sha: item.sha,
      patch: patch.slice(0, 12000),
      patch_truncated: patch.length > 12000,
    };
  });
}

function reviewEvidence(reviewContext: JsonObject, reviewContextPath: string, task: JsonObject): JsonObject {
  const metadata = (reviewContext.metadata as JsonObject | undefined) || {};
  const files = Array.isArray(reviewContext.files) ? (reviewContext.files as JsonObject[]) : [];
  const checkout = (reviewContext.checkout as JsonObject | undefined) || {};
  return {
    pr_number: reviewContext.pr_number,
    base_ref: metadata.base_ref,
    base_sha: metadata.base_sha,
    head_ref: metadata.head_ref,
    head_sha: metadata.head_sha,
    workspace_head_sha: checkout.workspace_head_sha,
    changed_file_count: files.length,
    changed_files: files.map((file) => file.filename).filter((file): file is JsonValue => file !== undefined),
    review_context_path: reviewContextPath,
    review_context_sha256: fileSha256(reviewContextPath),
  };
}

function fileSha256(path: string): string {
  return sha256(readFileSync(path));
}

async function publishResultIfConfigured(task: JsonObject, resultPath: string, token: string): Promise<void> {
  const publication = (task.publication as JsonObject | undefined) || {};
  const mode = publication.mode || "record_only";
  if (mode !== "comment") {
    task.publication_state = "held_for_issue_11_publication_gates";
    return;
  }

  const result = readJson<JsonObject>(resultPath, {});
  const taskData = (task.task as JsonObject | undefined) || {};
  const number = taskData.issue_number || taskData.pr_number;
  if (!number) {
    task.publication_state = "publication_skipped_no_issue_or_pr_number";
    return;
  }

  const body = publicationCommentBody(task, result);
  const repo = String(task.repository);
  try {
    const response = (await githubRequest("POST", `https://api.github.com/repos/${repo}/issues/${Number(number)}/comments`, token, {body})) as JsonObject;
    task.publication_state = "published_comment";
    task.publication_url = response.html_url;
    task.publication_comment_id = response.id;
  } catch (error) {
    task.publication_state = "publication_failed";
    task.publication_error = redactTokenish(String((error as Error).stack || error));
  }
}

function publicationCommentBody(task: JsonObject, result: JsonObject): string {
  const status = result.status || "unknown";
  const summary = String(result.summary || "No summary returned.");
  const prBody = String(result.pr_body || "");
  const filesChanged = Array.isArray(result.files_changed) ? result.files_changed : [];
  const commits = Array.isArray(result.commits) ? result.commits : [];
  const taskId = String(task.task_id || "");
  const evidence = (task.review_evidence as JsonObject | undefined) || {};
  const review = (result.review as JsonObject | undefined) || {};
  const parts = ["## Cody dogfood result", "", `**Status:** ${status}`, "", summary.trim()];
  if (prBody.trim() && prBody.trim() !== summary.trim()) {
    parts.push("", prBody.trim());
  }
  parts.push(...reviewFixLoopLines(task), "", "### Evidence");
  if (Object.keys(evidence).length) {
    const changedFiles = Array.isArray(evidence.changed_files) ? evidence.changed_files : [];
    parts.push(
      `- PR: #${evidence.pr_number}`,
      `- Base: \`${evidence.base_ref}\` @ \`${evidence.base_sha}\``,
      `- Head: \`${evidence.head_ref}\` @ \`${evidence.head_sha}\``,
      `- Checked-out workspace HEAD: \`${evidence.workspace_head_sha}\``,
      `- Changed files supplied to agent: ${evidence.changed_file_count}`,
      `- Review context SHA-256: \`${evidence.review_context_sha256}\``,
    );
    if (changedFiles.length) {
      parts.push(`- Files: ${changedFiles.slice(0, 20).map((file) => `\`${file}\``).join(", ")}`);
    }
  } else {
    parts.push("- No PR review evidence was captured for this run.");
  }
  parts.push(...structuredReviewLines(review));
  parts.push(
    "",
    `**Files changed:** ${filesChanged.length}`,
    `**Commits:** ${commits.length}`,
    "",
    `_Task \`${taskId}\`. Publication is enabled on the hosted test adapter only._`,
  );
  return parts.join("\n");
}

function reviewFixLoopLines(task: JsonObject): string[] {
  const loops = Array.isArray(task.review_fix_loops) ? (task.review_fix_loops as JsonObject[]) : [];
  if (!loops.length) {
    return [];
  }
  const lines = ["", "### Review fix loop"];
  for (const loop of loops) {
    lines.push(`- Iteration ${loop.iteration}: input findings ${loop.input_findings}, result \`${loop.result_status || "unknown"}\`, remaining findings ${loop.remaining_findings}.`);
  }
  if (loops.at(-1)?.remaining_findings) {
    lines.push(`- Loop stopped after ${loops.length} configured iteration(s); unresolved findings remain.`);
  }
  return lines;
}

function structuredReviewLines(review: JsonObject): string[] {
  if (!Object.keys(review).length) {
    return ["", "### Structured review", "- No structured review result was emitted."];
  }

  const lines = [
    "",
    "### Structured review",
    `- Mode: \`${review.mode || "unknown"}\``,
    `- Evidence status: \`${review.evidence_status || "unknown"}\``,
  ];
  const reviewedFiles = Array.isArray(review.reviewed_files) ? review.reviewed_files : [];
  lines.push(`- Reviewed files: ${reviewedFiles.length}`);
  if (reviewedFiles.length) {
    lines.push(`- Reviewed file list: ${reviewedFiles.slice(0, 20).map((path) => `\`${path}\``).join(", ")}`);
    if (reviewedFiles.length > 20) {
      lines.push("- Reviewed file list truncated after 20 entries.");
    }
  }
  const supportingFiles = Array.isArray(review.supporting_files) ? review.supporting_files : [];
  lines.push(`- Supporting files inspected: ${supportingFiles.length}`);
  if (supportingFiles.length) {
    lines.push(`- Supporting file list: ${supportingFiles.slice(0, 20).map((path) => `\`${path}\``).join(", ")}`);
    if (supportingFiles.length > 20) {
      lines.push("- Supporting file list truncated after 20 entries.");
    }
  }
  const findings = Array.isArray(review.findings) ? (review.findings as JsonObject[]) : [];
  lines.push(`- Findings: ${findings.length}`);
  findings.slice(0, 10).forEach((finding, index) => {
    let location = String(finding.file || "unknown file");
    if (finding.line !== undefined && finding.line !== null) {
      location = `${location}:${finding.line}`;
    }
    lines.push(`  ${index + 1}. \`${finding.severity || "unknown"}\` ${location} - ${finding.title || "Untitled finding"}`);
  });
  if (findings.length > 10) {
    lines.push("- Findings truncated after 10 entries.");
  }
  if (review.no_findings_reason) {
    lines.push(`- No-findings reason: ${review.no_findings_reason}`);
  }
  const testsRun = Array.isArray(review.tests_run) ? (review.tests_run as JsonObject[]) : [];
  lines.push(`- Tests reported by runtime: ${testsRun.length}`);
  testsRun.slice(0, 10).forEach((item) => {
    const summary = item.output_summary ? ` - ${item.output_summary}` : "";
    lines.push(`  - \`${item.command || "unknown command"}\`: \`${item.status || "unknown"}\`${summary}`);
  });
  if (testsRun.length > 10) {
    lines.push("- Test list truncated after 10 entries.");
  }
  const limitations = Array.isArray(review.limitations) ? review.limitations : [];
  lines.push(`- Limitations: ${limitations.length}`);
  limitations.slice(0, 10).forEach((limitation) => lines.push(`  - ${limitation}`));
  if (limitations.length > 10) {
    lines.push("- Limitation list truncated after 10 entries.");
  }
  return lines;
}

function loadCodexAccessToken(config: AdapterConfig): string | null {
  for (const path of codexTokenCandidates(config)) {
    try {
      const data = readJson<JsonObject>(path, {});
      const token = String(data.access_token || "").trim();
      if (token) {
        return token;
      }
    } catch {
      continue;
    }
  }
  return null;
}

function codexTokenCandidates(config: AdapterConfig): string[] {
  const candidates = [config.codexTokensPath];
  const covenHome = dirname(config.codexTokensPath);
  const registry = readJson<JsonObject>(join(covenHome, "accounts.json"), {});
  const active = (((registry.providers as JsonObject | undefined)?.codex as JsonObject | undefined)?.active as JsonValue) || "";
  if (active) {
    candidates.push(join(covenHome, "accounts", "codex", String(active), "codex_tokens.json"));
  }
  const accountsRoot = join(covenHome, "accounts", "codex");
  if (existsSync(accountsRoot)) {
    for (const entry of readdirSync(accountsRoot, {withFileTypes: true})) {
      if (entry.isDirectory()) {
        candidates.push(join(accountsRoot, entry.name, "codex_tokens.json"));
      }
    }
  }
  return candidates;
}

function redactedCommandResult(result: CommandResult): JsonObject {
  return {
    ...result,
    stdout: redactTokenish(result.stdout),
    stderr: redactTokenish(result.stderr),
  };
}

function redactTokenish(text: string): string {
  if (!text) {
    return text;
  }
  const markers = ["ghs_", "ghu_", "github_pat_", "x-access-token:"];
  let redacted = text;
  for (const marker of markers) {
    while (redacted.includes(marker)) {
      const index = redacted.indexOf(marker);
      let end = index + marker.length;
      while (end < redacted.length && !" \n\r\t'\"".includes(redacted[end])) {
        end += 1;
      }
      redacted = `${redacted.slice(0, index)}${marker}[redacted]${redacted.slice(end)}`;
    }
  }
  return redacted;
}

function failTask(path: string, task: JsonObject, reason: string, detail: string): JsonObject {
  task.state = "failed";
  task.failure_category = reason;
  task.failure_detail = redactTokenish(String(detail)).slice(-4000);
  task.updated_at = utcNow();
  writeJsonAtomic(path, task);
  return task;
}
