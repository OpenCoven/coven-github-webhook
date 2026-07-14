import {createHash, createHmac, createSign, randomUUID, timingSafeEqual} from "node:crypto";
import {existsSync, mkdirSync, readdirSync, readFileSync, renameSync, rmSync, statSync, writeFileSync} from "node:fs";
import {homedir} from "node:os";
import {basename, dirname, join, resolve, sep} from "node:path";
import {spawnSync} from "node:child_process";

export type JsonValue = null | boolean | number | string | JsonValue[] | JsonObject;
export type JsonObject = {[key: string]: JsonValue | undefined};

export interface AdapterConfig {
  rootDir: string;
  stateDir: string;
  deliveriesDir: string;
  tasksDir: string;
  publicationsDir: string;
  workspacesDir: string;
  attemptsDir: string;
  policyPath: string;
  privateKeyPath: string;
  privateKeyPem: string;
  appId: string;
  webhookSecret: string;
  covenCodeBin: string;
  covenCodeModel: string;
  maxReviewFixLoops: number;
  codexTokensPath: string;
  maxWebhookBodyBytes: number;
  demoMode: boolean;
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

class GithubApiError extends Error {
  constructor(
    readonly status: number,
    readonly responseBody: string,
    method: string,
    url: string,
  ) {
    super(`GitHub API ${method} ${url} failed (${status}): ${responseBody}`);
    this.name = "GithubApiError";
  }
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
    publicationsDir: join(stateDir, "publications"),
    workspacesDir: join(stateDir, "workspaces"),
    attemptsDir: join(stateDir, "attempts"),
    policyPath: resolve(env.COVEN_GITHUB_POLICY_PATH || join(rootDir, "coven-github-policy.json")),
    privateKeyPath: resolve(env.GITHUB_APP_PRIVATE_KEY_PATH || join(rootDir, ".coven-github-private-key.pem")),
    privateKeyPem: (env.GITHUB_APP_PRIVATE_KEY || "").trim(),
    appId: (env.GITHUB_APP_ID || "").trim(),
    webhookSecret: (env.GITHUB_WEBHOOK_SECRET || env.WEBHOOK_SECRET || "").trim(),
    covenCodeBin: (env.COVEN_CODE_BIN || "coven-code").trim() || "coven-code",
    covenCodeModel: (env.COVEN_CODE_MODEL || "gpt-5.5").trim(),
    maxReviewFixLoops: envInt(env.COVEN_REVIEW_FIX_LOOPS, 0, 0, 5),
    codexTokensPath: configuredCodexTokensPath(env),
    maxWebhookBodyBytes: MAX_WEBHOOK_BODY_BYTES,
    demoMode: ["1", "true", "yes"].includes((env.COVEN_GITHUB_DEMO_MODE || "").trim().toLowerCase()),
  };

  for (const directory of [config.deliveriesDir, config.tasksDir, config.publicationsDir, config.workspacesDir, config.attemptsDir]) {
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
  const privateKey = config.privateKeyPem || readFileSync(config.privateKeyPath, "utf8");
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
    signal: AbortSignal.timeout(30_000),
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
    throw new GithubApiError(response.status, raw, method, url);
  }
  return raw ? (JSON.parse(raw) as JsonValue) : {};
}

export async function githubRequestAllPages(url: string, token: string): Promise<JsonObject[]> {
  const items: JsonObject[] = [];
  for (let page = 1; page <= 100; page += 1) {
    const separator = url.includes("?") ? "&" : "?";
    const response = await githubRequest("GET", `${url}${separator}per_page=100&page=${page}`, token);
    if (!Array.isArray(response)) throw new Error(`GitHub paginated response was not an array: ${url}`);
    items.push(...(response as JsonObject[]));
    if (response.length < 100) return items;
  }
  throw new Error(`GitHub paginated response exceeded 100 pages: ${url}`);
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
    bot_usernames: policy.bot_usernames || [],
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
    if (config.demoMode) {
      return completeDemoTask(path, task, workspace, attemptDir);
    }

    const token = await installationToken(config, task.installation_id);
    const askpass = writeAskpass(attemptDir);
    const env: NodeJS.ProcessEnv = {
      ...sanitizedRuntimeEnvironment(process.env),
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
    refreshPublicationWorkspaceEvidence(task, workspace, env);
    await publishResultIfConfigured(config, task, String(finalCycle.result_path), token);
    writeJsonAtomic(path, task);
    return task;
  } catch (error) {
    return failTask(path, task, "infra_error", String((error as Error).stack || error));
  }
}

function refreshPublicationWorkspaceEvidence(task: JsonObject, workspace: string, env: NodeJS.ProcessEnv): void {
  const evidence = (task.review_evidence as JsonObject | undefined) || {};
  if (!Object.keys(evidence).length) return;
  const head = runCommand(["git", "rev-parse", "HEAD"], workspace, env, 30);
  const status = runCommand(["git", "status", "--porcelain"], workspace, env, 30);
  evidence.publication_workspace_head_sha = head.returncode === 0 ? head.stdout.trim() : "";
  evidence.publication_workspace_clean = status.returncode === 0 && status.stdout.trim() === "";
  task.review_evidence = evidence;
}

function completeDemoTask(path: string, task: JsonObject, workspace: string, attemptDir: string): JsonObject {
  mkdirSync(workspace, {recursive: true});
  const briefPath = join(attemptDir, "session-brief.json");
  const resultPath = join(attemptDir, "result.json");
  writeJsonAtomic(briefPath, sessionBrief(task, workspace, null));
  writeJsonAtomic(resultPath, {
    contract_version: "2",
    status: "success",
    summary: "Demo mode accepted a signed GitHub delivery, matched policy, and created a familiar task without external GitHub or coven-code calls.",
    files_changed: [],
    commits: [],
    review: {
      mode: "demo",
      evidence_status: "signed_delivery_policy_route",
      reviewed_files: [],
      supporting_files: [],
      findings: [],
      tests_run: [
        {
          command: "COVEN_GITHUB_DEMO_MODE=1 signed issues.labeled delivery",
          status: "passed",
          output_summary: "Webhook signature verified and example policy routed to familiar task.",
        },
      ],
      limitations: [
        "Demo mode does not mint GitHub installation tokens, clone repositories, run coven-code, or publish GitHub comments.",
      ],
    },
  });

  task.state = "completed";
  task.demo_mode = true;
  task.runtime_exit_code = 0;
  task.session_brief_path = briefPath;
  task.session_brief_sha256 = fileSha256(briefPath);
  task.result_path = resultPath;
  task.publication_state = "demo_mode_no_github_calls";
  task.updated_at = utcNow();
  writeJsonAtomic(path, task);
  return task;
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
  const files = await githubRequestAllPages(`https://api.github.com/repos/${repo}/pulls/${prNumber}/files`, token);

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
    changed_files: pr.changed_files,
  };
}

function summarizePrFiles(files: JsonObject[]): JsonObject[] {
  return (files || []).map((item) => {
    const patch = String(item.patch || "");
    const patchTruncated = patchEvidenceIncomplete(patch, Number(item.additions || 0), Number(item.deletions || 0));
    return {
      filename: item.filename,
      status: item.status,
      additions: item.additions,
      deletions: item.deletions,
      changes: item.changes,
      sha: item.sha,
      patch: patch.slice(0, 12000),
      patch_truncated: patch.length > 12000 || patchTruncated,
    };
  });
}

export function patchEvidenceIncomplete(patch: string, expectedAdditions: number, expectedDeletions: number): boolean {
  let additions = 0;
  let deletions = 0;
  let inHunk = false;
  for (const line of patch.split("\n")) {
    if (line.startsWith("@@")) {
      inHunk = true;
      continue;
    }
    if (!inHunk || line.startsWith("\\")) continue;
    if (line.startsWith("+")) additions += 1;
    else if (line.startsWith("-")) deletions += 1;
  }
  return additions !== expectedAdditions || deletions !== expectedDeletions;
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
    expected_changed_file_count: metadata.changed_files,
    changed_files: files.map((file) => file.filename).filter((file): file is JsonValue => file !== undefined),
    changed_file_lines: files.map((file) => ({path: file.filename, ...patchDiffLines(String(file.patch || ""))})),
    incomplete_patch_files: files
      .filter((file) => file.patch_truncated === true || !String(file.patch || "").trim())
      .map((file) => file.filename)
      .filter((file): file is JsonValue => file !== undefined),
    review_context_path: reviewContextPath,
    review_context_sha256: fileSha256(reviewContextPath),
  };
}

function patchDiffLines(patch: string): JsonObject {
  const leftLines: number[] = [];
  const rightLines: number[] = [];
  let leftLine: number | null = null;
  let rightLine: number | null = null;
  for (const line of patch.split("\n")) {
    const hunk = line.match(/^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@/);
    if (hunk) {
      leftLine = Number(hunk[1]);
      rightLine = Number(hunk[2]);
      continue;
    }
    if (leftLine === null || rightLine === null || line.startsWith("\\")) continue;
    if (line.startsWith("+")) {
      rightLines.push(rightLine);
      rightLine += 1;
    } else if (line.startsWith("-")) {
      leftLines.push(leftLine);
      leftLine += 1;
    } else {
      leftLines.push(leftLine);
      rightLines.push(rightLine);
      leftLine += 1;
      rightLine += 1;
    }
  }
  return {left_lines: leftLines, right_lines: rightLines};
}

function fileSha256(path: string): string {
  return sha256(readFileSync(path));
}

interface NormalizedReviewPublication {
  review: JsonObject;
  decision: "APPROVE" | "REQUEST_CHANGES" | "COMMENT";
  inlineComments: JsonObject[];
  validationIssues: string[];
  evidenceComplete: boolean;
}

function publicationRecordPath(config: AdapterConfig, repo: string, prNumber: number): string {
  return join(config.publicationsDir, `${sha256(`${repo}#${prNumber}`).slice(0, 24)}.json`);
}

interface PublicationLock {
  path: string;
  owner: string;
  heartbeat: NodeJS.Timeout;
}

async function acquirePublicationLock(config: AdapterConfig, key: string): Promise<PublicationLock> {
  const path = join(config.publicationsDir, `${sha256(key).slice(0, 24)}.lock`);
  const owner = randomUUID();
  while (true) {
    try {
      mkdirSync(path);
      const ownerPath = join(path, "owner");
      writeFileSync(ownerPath, owner, "utf8");
      const heartbeat = setInterval(() => {
        try {
          if (readFileSync(ownerPath, "utf8") === owner) writeFileSync(ownerPath, owner, "utf8");
        } catch {
          clearInterval(heartbeat);
        }
      }, 10_000);
      heartbeat.unref();
      return {path, owner, heartbeat};
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
      try {
        const ownerPath = join(path, "owner");
        const leaseMtime = existsSync(ownerPath) ? statSync(ownerPath).mtimeMs : statSync(path).mtimeMs;
        if (Date.now() - leaseMtime > 2 * 60 * 1000) {
          const stalePath = `${path}.stale-${owner}`;
          renameSync(path, stalePath);
          rmSync(stalePath, {recursive: true, force: true});
          continue;
        }
      } catch (retryError) {
        if ((retryError as NodeJS.ErrnoException).code !== "ENOENT") {
          if ((retryError as NodeJS.ErrnoException).code !== "EEXIST") throw retryError;
        }
        continue;
      }
      await new Promise((resolveDelay) => setTimeout(resolveDelay, 100));
    }
  }
}

function releasePublicationLock(lock: PublicationLock): void {
  clearInterval(lock.heartbeat);
  try {
    if (readFileSync(join(lock.path, "owner"), "utf8") !== lock.owner) return;
    const releasePath = `${lock.path}.release-${lock.owner}`;
    renameSync(lock.path, releasePath);
    rmSync(releasePath, {recursive: true, force: true});
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }
}

function publicationIdentity(task: JsonObject, result: JsonObject): string {
  const evidence = (task.review_evidence as JsonObject | undefined) || {};
  return sha256(stableCompactStringify({
    task_id: task.task_id,
    head_sha: evidence.head_sha,
    result,
  }));
}

interface PublicationTrust {
  secret: string;
  target: string;
  botUsernames: Set<string>;
}

function publicationTrust(config: AdapterConfig, task: JsonObject, target: string): PublicationTrust {
  if (!config.webhookSecret) throw new Error("GITHUB_WEBHOOK_SECRET is required to sign publication identities");
  const policy = (task.policy_snapshot as JsonObject | undefined) || {};
  return {
    secret: config.webhookSecret,
    target,
    botUsernames: new Set((Array.isArray(policy.bot_usernames) ? policy.bot_usernames : []).map((name) => String(name).toLowerCase())),
  };
}

function markerCreatedAt(taskCreatedAt?: JsonValue): string {
  return typeof taskCreatedAt === "string" && Number.isFinite(Date.parse(taskCreatedAt)) ? taskCreatedAt : "";
}

function publicationProof(trust: PublicationTrust, identity: string, createdAt: string): string {
  return createHmac("sha256", trust.secret).update(`${trust.target}\0${identity}\0${createdAt}`).digest("hex");
}

function publicationMarker(trust: PublicationTrust, identity: string, taskCreatedAt?: JsonValue): string {
  const createdAt = markerCreatedAt(taskCreatedAt);
  return [
    `<!-- covencat-publication:${identity} -->`,
    createdAt ? `<!-- covencat-task-created:${createdAt} -->` : "",
    `<!-- covencat-publication-proof:${publicationProof(trust, identity, createdAt)} -->`,
  ].filter(Boolean).join("\n");
}

function publicationIdentityFromBody(item: JsonObject): string {
  return String(item.body || "").match(/<!-- covencat-publication:([a-f0-9]{64}) -->/)?.[1] || "";
}

function trustedPublication(item: JsonObject, trust: PublicationTrust): boolean {
  const body = String(item.body || "");
  const identity = publicationIdentityFromBody(item);
  const createdAt = body.match(/<!-- covencat-task-created:([^>]+) -->/)?.[1] || "";
  const proof = body.match(/<!-- covencat-publication-proof:([a-f0-9]{64}) -->/)?.[1] || "";
  const user = (item.user as JsonObject | undefined) || {};
  const login = String(user.login || "").toLowerCase();
  if (!identity || !proof || user.type !== "Bot" || (trust.botUsernames.size && !trust.botUsernames.has(login))) return false;
  const actual = Buffer.from(proof, "hex");
  const expected = Buffer.from(publicationProof(trust, identity, createdAt), "hex");
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}

function trustedPublications(items: JsonObject[], trust: PublicationTrust): JsonObject[] {
  return items.filter((item) => trustedPublication(item, trust));
}

function publicationWithIdentity(items: JsonObject[], identity: string, trust: PublicationTrust): JsonObject | undefined {
  return latestCovencatPublication(trustedPublications(items, trust).filter((item) => publicationIdentityFromBody(item) === identity));
}

function latestCovencatPublication(items: JsonObject[]): JsonObject | undefined {
  return items.reduce<JsonObject | undefined>((latest, item) => !latest || publicationGeneration(item) >= publicationGeneration(latest) ? item : latest, undefined);
}

function publicationGeneration(item: JsonObject): number {
  const bodyCreatedAt = String(item.body || "").match(/<!-- covencat-task-created:([^>]+) -->/)?.[1];
  const created = Date.parse(bodyCreatedAt || String(item.submitted_at || item.published_at || ""));
  return Number.isFinite(created) ? created : Number(item.id || 0);
}

function previousCovencatPublication(items: JsonObject[], identity: string, trust: PublicationTrust): JsonObject | undefined {
  return latestCovencatPublication(trustedPublications(items, trust).filter((item) => {
    const itemIdentity = publicationIdentityFromBody(item);
    return itemIdentity && itemIdentity !== identity;
  }));
}

function clearPublicationError(task: JsonObject): void {
  delete task.publication_error;
}

function inlineLocationError(error: unknown): boolean {
  return error instanceof GithubApiError && error.status === 422 && /(comment|diff|line|position|pullrequestreviewcomment)/i.test(error.responseBody);
}

function selfReviewError(error: unknown): boolean {
  return error instanceof GithubApiError && error.status === 422 && /(?:approve|request changes?).{0,40}(?:own|your) pull request|own pull request.{0,40}(?:approve|request changes?)/i.test(error.responseBody);
}

function safePublicationText(value: string, maxLength = 60_000): string {
  return redactTokenish(value).slice(0, maxLength);
}

function decisiveReviewState(value: JsonValue | undefined): boolean {
  return ["APPROVE", "APPROVED", "REQUEST_CHANGES", "CHANGES_REQUESTED"].includes(String(value || "").toUpperCase());
}

function priorReviewFromRecord(record: JsonObject): JsonObject {
  return {
    id: record.previous_review_id,
    state: record.previous_decision,
    html_url: record.previous_review_url,
    identity: record.previous_identity,
  };
}

function publicationRecord(
  task: JsonObject,
  identity: string,
  review: JsonObject,
  decision: JsonValue | undefined,
  previous: JsonObject,
  pendingDismissals: JsonObject[],
  submissionPending = false,
): JsonObject {
  return {
    identity,
    review_id: review.id,
    review_url: review.html_url,
    decision,
    task_id: task.task_id,
    task_created_at: task.created_at,
    head_sha: ((task.review_evidence as JsonObject | undefined) || {}).head_sha,
    published_at: review.submitted_at || utcNow(),
    previous_identity: previous.identity || publicationIdentityFromBody(previous),
    previous_review_id: previous.review_id || previous.id,
    previous_review_url: previous.review_url || previous.html_url,
    previous_decision: previous.decision || previous.state,
    supersession_pending: pendingDismissals.length > 0,
    pending_dismissals: pendingDismissals,
    submission_pending: submissionPending,
    desired_decision: submissionPending ? decision : undefined,
    review_body: submissionPending ? review.body : undefined,
  };
}

function reviewReference(review: JsonObject): JsonObject {
  return {
    id: review.review_id || review.id,
    state: review.decision || review.state,
    html_url: review.review_url || review.html_url,
    identity: review.identity || publicationIdentityFromBody(review),
  };
}

function pendingDismissalsFromRecord(record: JsonObject): JsonObject[] {
  const pending = Array.isArray(record.pending_dismissals)
    ? record.pending_dismissals.filter((item): item is JsonObject => Boolean(item) && typeof item === "object" && !Array.isArray(item))
    : [];
  if (!pending.length && record.supersession_pending === true) {
    const legacy = priorReviewFromRecord(record);
    if (legacy.id) pending.push(legacy);
  }
  return pending;
}

function priorDecisiveReviews(items: JsonObject[], identity: string, trust: PublicationTrust, record: JsonObject): JsonObject[] {
  const candidates = [
    ...trustedPublications(items, trust).filter((item) => decisiveReviewState(item.state)),
    ...(record.identity && record.identity !== identity && decisiveReviewState(record.decision) ? [record] : []),
    ...pendingDismissalsFromRecord(record),
  ];
  const unique = new Map<number, JsonObject>();
  for (const candidate of candidates) {
    const reference = reviewReference(candidate);
    const id = Number(reference.id || 0);
    if (id && decisiveReviewState(reference.state)) unique.set(id, reference);
  }
  return [...unique.values()];
}

async function reconcilePriorDecisiveReviews(
  repo: string,
  prNumber: number,
  token: string,
  previousReviews: JsonObject[],
  current: JsonObject,
  task: JsonObject,
): Promise<JsonObject[]> {
  const currentReviewId = Number(current.review_id || current.id || 0);
  const pending: JsonObject[] = [];
  const errors: string[] = [];
  let attempted = 0;
  for (const previous of previousReviews) {
    const previousReviewId = Number(previous.review_id || previous.id || 0);
    const previousState = previous.decision || previous.state;
    if (!previousReviewId || previousReviewId === currentReviewId || !decisiveReviewState(previousState)) continue;
    attempted += 1;
    try {
      await githubRequest("PUT", `https://api.github.com/repos/${repo}/pulls/${prNumber}/reviews/${previousReviewId}/dismissals`, token, {
        message: `Superseded by ${String(current.review_url || current.html_url || "a newer covencat review")}`,
        event: "DISMISS",
      });
    } catch (error) {
      pending.push(reviewReference(previous));
      errors.push(redactTokenish(String((error as Error).stack || error)));
    }
  }
  if (!attempted) {
    delete task.publication_supersession_state;
    delete task.publication_supersession_error;
    return [];
  }
  if (!pending.length) {
    task.publication_supersession_state = "prior_decisive_review_dismissed";
    delete task.publication_supersession_error;
    return [];
  }
  task.publication_supersession_state = "prior_decisive_review_dismissal_failed";
  task.publication_supersession_error = errors.join("\n");
  if (pending.length) {
    const currentBody = String(current.body || "");
    const warning = "_Warning: GitHub did not permit covencat to dismiss the prior decisive review; maintainers should dismiss it manually._";
    if (currentReviewId && currentBody && !currentBody.includes(warning)) {
      try {
        await githubRequest("PUT", `https://api.github.com/repos/${repo}/pulls/${prNumber}/reviews/${currentReviewId}`, token, {
          body: safePublicationText(`${currentBody}\n\n${warning}`),
        });
      } catch (updateError) {
        task.publication_supersession_error = redactTokenish(`${task.publication_supersession_error}\n${String((updateError as Error).stack || updateError)}`);
      }
    }
  }
  return pending;
}

async function reconcileReplacementSupersession(
  repo: string,
  prNumber: number,
  token: string,
  priorReviews: JsonObject[],
  submitted: SubmittedReview,
  evidenceComplete: boolean,
  task: JsonObject,
): Promise<JsonObject[]> {
  if (submitted.staleEvidence || !evidenceComplete) {
    if (priorReviews.length) {
      task.publication_supersession_state = submitted.staleEvidence
        ? "prior_decisive_review_retained_for_stale_replacement"
        : "prior_decisive_review_retained_for_incomplete_replacement";
      delete task.publication_supersession_error;
    }
    return priorReviews;
  }
  return reconcilePriorDecisiveReviews(repo, prNumber, token, priorReviews, submitted.review, task);
}

interface SubmittedReview {
  review: JsonObject;
  body: string;
  decision: string;
  staleAfterSubmit: boolean;
  staleEvidence: boolean;
}

async function currentPullHead(repo: string, prNumber: number, token: string): Promise<string> {
  const pr = (await githubRequest("GET", `https://api.github.com/repos/${repo}/pulls/${prNumber}`, token)) as JsonObject;
  return String(((pr.head as JsonObject | undefined) || {}).sha || "");
}

async function dismissReviewForStaleHead(
  repo: string,
  prNumber: number,
  token: string,
  review: JsonObject,
  body: string,
): Promise<SubmittedReview> {
  const reviewId = Number(review.id || review.review_id || 0);
  if (!reviewId) throw new Error("GitHub did not return an ID for the stale decisive review");
  await githubRequest("PUT", `https://api.github.com/repos/${repo}/pulls/${prNumber}/reviews/${reviewId}/dismissals`, token, {
    message: "Dismissed automatically because the PR head changed while covencat was submitting the review.",
    event: "DISMISS",
  });
  const publishedBody = safePublicationText(`${body}\n\n_This decisive review was dismissed automatically because the PR head changed during submission._`);
  await githubRequest("PUT", `https://api.github.com/repos/${repo}/pulls/${prNumber}/reviews/${reviewId}`, token, {body: publishedBody});
  return {review: {...review, state: "DISMISSED", body: publishedBody}, body: publishedBody, decision: "DISMISSED", staleAfterSubmit: true, staleEvidence: true};
}

async function submitPendingReview(
  repo: string,
  prNumber: number,
  token: string,
  pendingReview: JsonObject,
  desiredDecision: "APPROVE" | "REQUEST_CHANGES" | "COMMENT",
  evidenceHead: string,
  body: string,
): Promise<SubmittedReview> {
  const reviewId = Number(pendingReview.id || pendingReview.review_id || 0);
  if (!reviewId) throw new Error("GitHub did not return an ID for the pending review");
  let decision: "APPROVE" | "REQUEST_CHANGES" | "COMMENT" = desiredDecision;
  let publishedBody = body;
  let staleEvidence = false;
  const headBeforeSubmit = await currentPullHead(repo, prNumber, token);
  if (headBeforeSubmit !== evidenceHead && decisiveReviewState(decision)) {
    staleEvidence = true;
    decision = "COMMENT";
    publishedBody = safePublicationText(`${body}\n\n_The PR head changed before this review was submitted, so stale evidence was published as COMMENT._`);
  }
  let response: JsonObject;
  try {
    response = (await githubRequest("POST", `https://api.github.com/repos/${repo}/pulls/${prNumber}/reviews/${reviewId}/events`, token, {
      event: decision,
      body: publishedBody,
    })) as JsonObject;
  } catch (error) {
    if (!selfReviewError(error) || !decisiveReviewState(decision)) throw error;
    decision = "COMMENT";
    publishedBody = safePublicationText(`${body}\n\n_GitHub does not allow the App to submit a decisive review on its own pull request, so this was published as COMMENT._`);
    response = (await githubRequest("POST", `https://api.github.com/repos/${repo}/pulls/${prNumber}/reviews/${reviewId}/events`, token, {
      event: decision,
      body: publishedBody,
    })) as JsonObject;
  }
  let review: JsonObject = {...pendingReview, ...response, id: response.id || pendingReview.id, body: publishedBody};
  if (decisiveReviewState(decision)) {
    const headAfterSubmit = await currentPullHead(repo, prNumber, token);
    if (headAfterSubmit !== evidenceHead) {
      return dismissReviewForStaleHead(repo, prNumber, token, review, publishedBody);
    }
  }
  return {review, body: publishedBody, decision, staleAfterSubmit: false, staleEvidence};
}

function repositoryPath(value: JsonValue | undefined): string | null {
  if (typeof value !== "string") return null;
  const path = value.trim();
  if (!path || path.includes("\n") || path.includes("\r") || /^\d+:\s/.test(path) || path.startsWith("/") || path.includes("\\") || path.split("/").some((part) => !part || part === "." || part === "..")) {
    return null;
  }
  return path;
}

function repositoryPathExists(root: string | undefined, path: string): boolean {
  if (!root) return true;
  const normalizedRoot = resolve(root);
  const candidate = resolve(normalizedRoot, path);
  return candidate.startsWith(`${normalizedRoot}${sep}`) && existsSync(candidate);
}

function actionableFinding(finding: JsonObject): boolean {
  return !["info", "informational", "nit", "note"].includes(String(finding.severity || "").toLowerCase()) && Boolean(finding.title || finding.body || finding.recommendation);
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function validFinding(finding: JsonObject): boolean {
  const allowed = new Set(["info", "low", "medium", "high", "critical"]);
  const line = finding.line;
  return allowed.has(String(finding.severity || ""))
    && typeof finding.file === "string"
    && (line === null || (typeof line === "number" && Number.isInteger(line) && line >= 1))
    && typeof finding.title === "string"
    && typeof finding.body === "string"
    && (finding.recommendation === null || typeof finding.recommendation === "string");
}

export function normalizeReviewPublication(task: JsonObject, result: JsonObject, currentHeadSha?: string, repositoryRoot?: string): NormalizedReviewPublication {
  const review = {...((result.review as JsonObject | undefined) || {})};
  const evidence = (task.review_evidence as JsonObject | undefined) || {};
  const changedFiles = new Set((Array.isArray(evidence.changed_files) ? evidence.changed_files : [])
    .map((path) => repositoryPath(path))
    .filter((path): path is string => path !== null));
  const changedLines = new Map<string, {LEFT: Set<number>; RIGHT: Set<number>}>();
  for (const item of (Array.isArray(evidence.changed_file_lines) ? evidence.changed_file_lines : [])) {
    if (!item || typeof item !== "object" || Array.isArray(item)) continue;
    const file = repositoryPath((item as JsonObject).path);
    const left = (item as JsonObject).left_lines;
    const right = (item as JsonObject).right_lines;
    if (file) {
      changedLines.set(file, {
        LEFT: new Set((Array.isArray(left) ? left : []).map(Number).filter((line) => Number.isInteger(line) && line > 0)),
        RIGHT: new Set((Array.isArray(right) ? right : []).map(Number).filter((line) => Number.isInteger(line) && line > 0)),
      });
    }
  }
  const validationIssues: string[] = [];
  if (String(result.contract_version || "") !== "2") validationIssues.push("result contract_version is not v2");
  if (!["success", "failure", "partial", "needs_input"].includes(String(result.status || ""))) validationIssues.push("result status is invalid");
  if (typeof result.summary !== "string" || typeof result.pr_body !== "string") validationIssues.push("result summary or pr_body is invalid");
  if (!Array.isArray(result.commits) || !Array.isArray(result.files_changed)) validationIssues.push("result commits or files_changed is invalid");
  for (const field of ["reviewed_files", "supporting_files", "findings", "tests_run", "limitations"]) {
    if (!Array.isArray(review[field])) validationIssues.push(`review.${field} is missing or invalid`);
  }
  if (!["none", "pull_request", "review_comment"].includes(String(review.mode || ""))) validationIssues.push("review mode is invalid");
  if (!["not_applicable", "complete", "partial", "missing"].includes(String(review.evidence_status || ""))) validationIssues.push("review evidence_status is invalid");
  if (!("no_findings_reason" in review) || (review.no_findings_reason !== null && typeof review.no_findings_reason !== "string")) validationIssues.push("review no_findings_reason is missing or invalid");
  const reviewedFiles = (Array.isArray(review.reviewed_files) ? review.reviewed_files : [])
    .map((path) => repositoryPath(path));
  const supportingFiles = (Array.isArray(review.supporting_files) ? review.supporting_files : [])
    .map((path) => repositoryPath(path));
  const suppliedInspectedPresent = Array.isArray(result.files_inspected);
  const suppliedInspected = (suppliedInspectedPresent ? result.files_inspected as JsonValue[] : [])
    .map((path) => repositoryPath(path));
  const validReviewedFiles = reviewedFiles.filter((path): path is string => path !== null && changedFiles.has(path));
  const invalidReviewedFiles = reviewedFiles.filter((path) => path === null || !changedFiles.has(path));
  const reviewedFileSet = new Set(validReviewedFiles);
  if (review.mode !== "pull_request") validationIssues.push("result did not declare pull_request review mode");
  if (review.evidence_status !== "complete") validationIssues.push("review evidence was not marked complete");
  if (result.status !== "success") validationIssues.push("runtime result was not successful");
  if (!String(evidence.head_sha || "").trim()) validationIssues.push("PR head revision is missing");
  if (!String(evidence.workspace_head_sha || "").trim()) validationIssues.push("checked-out revision is missing");
  if (evidence.workspace_head_sha !== evidence.head_sha) validationIssues.push("checked-out revision does not match the captured PR head");
  if (!String(evidence.publication_workspace_head_sha || "").trim()) validationIssues.push("post-run workspace revision is missing");
  if (evidence.publication_workspace_head_sha !== evidence.head_sha) validationIssues.push("post-run workspace revision does not match the captured PR head");
  if (evidence.publication_workspace_clean !== true) validationIssues.push("post-run workspace contains uncommitted changes");
  if (currentHeadSha !== undefined && !currentHeadSha) validationIssues.push("current PR head could not be verified");
  if (currentHeadSha && currentHeadSha !== evidence.head_sha) validationIssues.push("PR head changed after review evidence was captured");
  if (!changedFiles.size) validationIssues.push("no changed-file evidence was captured");
  if (Number(evidence.changed_file_count) !== changedFiles.size) validationIssues.push("changed-file count does not match captured changed files");
  if (Number(evidence.expected_changed_file_count) !== changedFiles.size) validationIssues.push("captured files do not cover the PR changed-file count");
  if (!Array.isArray(evidence.incomplete_patch_files)) validationIssues.push("diff evidence completeness is missing");
  if (Array.isArray(evidence.incomplete_patch_files) && evidence.incomplete_patch_files.length) validationIssues.push("captured diff evidence is incomplete or truncated");
  if (!reviewedFiles.length) validationIssues.push("no reviewed files were reported");
  if (invalidReviewedFiles.length) validationIssues.push("reviewed files are not all changed files in the captured PR revision");
  if ([...changedFiles].some((path) => !reviewedFileSet.has(path))) validationIssues.push("review scope does not cover every changed file");
  const verifiedEvidencePath = (path: string): boolean => changedFiles.has(path) || repositoryPathExists(repositoryRoot, path);
  if (suppliedInspected.some((path) => path === null || (path !== null && !verifiedEvidencePath(path)))) validationIssues.push("files_inspected contains an invalid or missing repository path");
  const suppliedInspectedSet = new Set(suppliedInspected.filter((path): path is string => path !== null));
  const validSupportingFiles = supportingFiles.filter((path): path is string => path !== null && repositoryPathExists(repositoryRoot, path));
  const expectedInspectedSet = new Set([...reviewedFileSet, ...validSupportingFiles]);
  if (suppliedInspectedPresent && ([...suppliedInspectedSet].some((path) => !expectedInspectedSet.has(path)) || [...expectedInspectedSet].some((path) => !suppliedInspectedSet.has(path)))) {
    validationIssues.push("files_inspected does not match reviewed_files plus supporting_files");
  }
  if (supportingFiles.some((path) => path === null || (path !== null && !repositoryPathExists(repositoryRoot, path)))) validationIssues.push("supporting_files contains an invalid or missing repository path");
  const limitations = Array.isArray(review.limitations) ? review.limitations.filter((item) => String(item || "").trim()) : [];
  if (Array.isArray(review.limitations) && review.limitations.some((item) => typeof item !== "string")) validationIssues.push("review limitations contains an invalid entry");
  if (limitations.length) validationIssues.push("review reported limitations");

  const testsRun = (Array.isArray(review.tests_run) ? review.tests_run : [])
    .filter((item): item is JsonObject => Boolean(item) && typeof item === "object" && !Array.isArray(item));
  if (Array.isArray(review.tests_run) && testsRun.length !== review.tests_run.length) validationIssues.push("tests_run contains an invalid entry");
  if (!testsRun.length) validationIssues.push("no test execution evidence was reported");
  const normalizedTests: JsonObject[] = [];
  for (const test of testsRun) {
    const command = String(test.command || "").trim();
    const status = String(test.status || "").toLowerCase();
    const output = String(test.output_summary || "").trim();
    const narrative = `${String(result.summary || "")}\n${String(result.pr_body || "")}`.toLowerCase();
    const validShape = typeof test.command === "string"
      && ["passed", "failed", "not_run", "unknown"].includes(status)
      && (test.output_summary === null || typeof test.output_summary === "string");
    if (!validShape) validationIssues.push(`test evidence for ${command || "an unnamed command"} is malformed`);
    const narrativeDeniesExecution = /\b(?:tests?|checks?|commands?)\b.{0,50}\b(?:not (?:run|executed)|skip(?:ped)?|unable to (?:run|execute))\b/i.test(narrative)
      || /\b(?:not (?:run|executed)|skip(?:ped)?|unable to (?:run|execute))\b.{0,50}\b(?:tests?|checks?|commands?)\b/i.test(narrative);
    const commandDenied = command && new RegExp(`${escapeRegExp(command.toLowerCase())}.{0,30}(?:not (?:run|executed)|skip(?:ped)?|unable)`, "i").test(narrative);
    const invalidPass = status === "passed" && (!validShape || !command || !output || /\b(not[ _-]?run|skip(?:ped)?)\b/i.test(output) || narrativeDeniesExecution || commandDenied);
    if (invalidPass) {
      validationIssues.push(`test evidence for ${command || "an unnamed command"} is contradictory or incomplete`);
      normalizedTests.push({...test, status: "unverified", output_summary: "Reported as passed, but supporting execution evidence was missing or contradictory."});
    } else {
      normalizedTests.push({...test, command: command || "unknown command", status: status || "unknown", output_summary: output});
      if (status !== "passed") validationIssues.push(`test ${command || "an unnamed command"} did not pass`);
    }
  }

  const findings = (Array.isArray(review.findings) ? review.findings : [])
    .filter((item): item is JsonObject => Boolean(item) && typeof item === "object" && !Array.isArray(item));
  if (Array.isArray(review.findings) && findings.length !== review.findings.length) validationIssues.push("findings contains an invalid entry");
  const validFindings = findings.filter(validFinding);
  if (validFindings.length !== findings.length) validationIssues.push("findings contains a malformed finding");
  if (findings.length && review.no_findings_reason !== null) validationIssues.push("a no-findings reason was reported alongside findings");
  const scopedFindings = validFindings.filter((finding) => {
    const path = repositoryPath(finding.file);
    return Boolean(path && changedFiles.has(path));
  });
  if (scopedFindings.length !== validFindings.length) validationIssues.push("findings contains a path outside the verified changed-file set");
  const inlineComments: JsonObject[] = [];
  for (const finding of scopedFindings) {
    const path = repositoryPath(finding.file);
    const line = Number(finding.line);
    const locations = path ? changedLines.get(path) : undefined;
    const side = locations?.RIGHT.has(line) ? "RIGHT" : locations?.LEFT.has(line) ? "LEFT" : null;
    if (path && side && changedFiles.has(path) && Number.isInteger(line) && line > 0 && actionableFinding(finding)) {
      inlineComments.push({
        path,
        line,
        side,
        body: findingCommentBody(finding),
      });
    }
  }

  if (!findings.length && !String(review.no_findings_reason || "").trim()) validationIssues.push("no-findings review is missing its justification");
  const evidenceComplete = validationIssues.length === 0;
  const actionable = scopedFindings.some(actionableFinding);
  review.evidence_status = evidenceComplete ? "complete" : "partial";
  review.reviewed_files = validReviewedFiles;
  review.supporting_files = validSupportingFiles;
  review.findings = findings;
  review.tests_run = normalizedTests;
  review.limitations = limitations;
  return {
    review,
    decision: evidenceComplete && !findings.length ? "APPROVE" : evidenceComplete && actionable ? "REQUEST_CHANGES" : "COMMENT",
    inlineComments,
    validationIssues,
    evidenceComplete,
  };
}

function findingCommentBody(finding: JsonObject): string {
  const parts = [`**${String(finding.severity || "finding")}**: ${String(finding.title || "Untitled finding")}`];
  if (finding.body) parts.push("", String(finding.body));
  if (finding.recommendation) parts.push("", `Suggested resolution: ${String(finding.recommendation)}`);
  return safePublicationText(parts.join("\n"), 6000);
}

export async function publishResultIfConfigured(config: AdapterConfig, task: JsonObject, resultPath: string, token: string): Promise<void> {
  const publication = (task.publication as JsonObject | undefined) || {};
  const mode = publication.mode || "record_only";
  if (mode !== "comment") {
    task.publication_state = "held_for_issue_11_publication_gates";
    return;
  }

  const result = readJson<JsonObject>(resultPath, {});
  const taskData = (task.task as JsonObject | undefined) || {};
  const prNumber = prNumberForTask(task);
  const number = taskData.issue_number || taskData.pr_number || prNumber;
  if (!number) {
    task.publication_state = "publication_skipped_no_issue_or_pr_number";
    return;
  }

  const repo = String(task.repository);
  const identity = publicationIdentity(task, result);
  const publicationLock = await acquirePublicationLock(config, `${repo}#${prNumber ? `pr:${prNumber}` : `issue:${number}`}`);
  try {
    try {
      const hasReview = Object.keys((result.review as JsonObject | undefined) || {}).length > 0;
      const operationalFailure = ["failure", "needs_input"].includes(String(result.status || "")) && !hasReview;
      if (prNumber && !operationalFailure) {
        if (task.publication_identity === identity && task.publication_review_id && task.publication_supersession_state !== "prior_decisive_review_dismissal_failed") {
          task.publication_state = "publication_skipped_duplicate";
          clearPublicationError(task);
          return;
        }
        const recordPath = publicationRecordPath(config, repo, prNumber);
        const stored = readJson<JsonObject>(recordPath, {});
        if (stored.identity === identity && stored.review_id && stored.supersession_pending !== true && stored.submission_pending !== true) {
          task.publication_state = "publication_skipped_duplicate";
          task.publication_identity = identity;
          task.publication_review_id = stored.review_id;
          task.publication_url = stored.review_url;
          clearPublicationError(task);
          return;
        }

        const target = `${repo}#pr:${prNumber}`;
        const trust = publicationTrust(config, task, target);
        const currentHeadSha = await currentPullHead(repo, prNumber, token);
        const reviews = await githubRequestAllPages(`https://api.github.com/repos/${repo}/pulls/${prNumber}/reviews`, token);
        const trustedReviews = trustedPublications(reviews, trust);
        const evidence = (task.review_evidence as JsonObject | undefined) || {};
        const currentHeadRemote = latestCovencatPublication(trustedReviews.filter((review) => String(review.commit_id || "") === currentHeadSha));
        const evidenceHeadRemote = latestCovencatPublication(trustedReviews.filter((review) => String(review.commit_id || "") === String(evidence.head_sha || ""))) || {};
        const evidenceHeadRemoteIdentity = publicationIdentityFromBody(evidenceHeadRemote);
        const taskGeneration = Date.parse(String(task.created_at || ""));
        const staleRevision = evidence.head_sha !== currentHeadSha
          && (Boolean(currentHeadRemote) || String(stored.head_sha || "") === currentHeadSha);
        const staleGeneration = evidenceHeadRemoteIdentity
          && evidenceHeadRemoteIdentity !== identity
          && Number.isFinite(taskGeneration)
          && publicationGeneration(evidenceHeadRemote) > taskGeneration;
        const existing = publicationWithIdentity(reviews, identity, trust);
        if (staleRevision || staleGeneration) {
          if (existing && String(existing.state || "").toUpperCase() === "PENDING") {
            await githubRequest("DELETE", `https://api.github.com/repos/${repo}/pulls/${prNumber}/reviews/${Number(existing.id)}`, token);
          } else if (existing && staleRevision && decisiveReviewState(existing.state)) {
            await dismissReviewForStaleHead(repo, prNumber, token, existing, String(existing.body || ""));
          }
          task.publication_state = staleRevision ? "publication_skipped_stale_revision" : "publication_skipped_stale_run";
          task.publication_identity = identity;
          clearPublicationError(task);
          return;
        }

        if (existing && evidenceHeadRemoteIdentity && evidenceHeadRemoteIdentity !== identity && publicationGeneration(evidenceHeadRemote) >= publicationGeneration(existing)) {
          if (String(existing.state || "").toUpperCase() === "PENDING") {
            await githubRequest("DELETE", `https://api.github.com/repos/${repo}/pulls/${prNumber}/reviews/${Number(existing.id)}`, token);
          }
          task.publication_state = "publication_skipped_stale_run";
          task.publication_identity = identity;
          clearPublicationError(task);
          return;
        }
        const previous = previousCovencatPublication(reviews, identity, trust)
          || (stored.identity !== identity ? stored : priorReviewFromRecord(stored));
        const repositoryRoot = join(config.workspacesDir, String(task.task_id), "repo");
        const normalized = normalizeReviewPublication(task, result, currentHeadSha, repositoryRoot);
        const priorDecisive = priorDecisiveReviews(reviews, identity, trust, stored);
        if (existing) {
          const recoveredPending = String(existing.state || "").toUpperCase() === "PENDING";
          let submitted = recoveredPending
            ? await submitPendingReview(repo, prNumber, token, existing, normalized.decision, String(evidence.head_sha || ""), String(existing.body || ""))
            : {review: existing, body: String(existing.body || ""), decision: String(existing.state || normalized.decision), staleAfterSubmit: false, staleEvidence: false};
          if (!recoveredPending && decisiveReviewState(submitted.decision) && currentHeadSha !== evidence.head_sha) {
            submitted = await dismissReviewForStaleHead(repo, prNumber, token, submitted.review, submitted.body);
          }
          const pendingDismissals = await reconcileReplacementSupersession(repo, prNumber, token, priorDecisive, submitted, normalized.evidenceComplete, task);
          const record = publicationRecord(task, identity, submitted.review, submitted.decision, previous, pendingDismissals);
          writeJsonAtomic(recordPath, record);
          task.publication_state = submitted.staleAfterSubmit ? "published_review_dismissed_stale" : submitted.staleEvidence ? "published_review_stale_comment" : recoveredPending ? "published_review_recovered" : "publication_skipped_duplicate";
          task.publication_identity = identity;
          task.publication_review_id = submitted.review.id;
          task.publication_url = submitted.review.html_url;
          task.publication_decision = submitted.decision;
          clearPublicationError(task);
          return;
        }

        if (stored.identity === identity && stored.review_id) {
          const current = {
            id: stored.review_id,
            review_id: stored.review_id,
            html_url: stored.review_url,
            review_url: stored.review_url,
            body: stored.review_body,
          };
          let submitted = stored.submission_pending === true
            ? await submitPendingReview(repo, prNumber, token, current, normalized.decision, String(evidence.head_sha || ""), String(stored.review_body || ""))
            : {review: current, body: String(stored.review_body || ""), decision: String(stored.decision || normalized.decision), staleAfterSubmit: false, staleEvidence: false};
          if (stored.submission_pending !== true && decisiveReviewState(submitted.decision) && currentHeadSha !== evidence.head_sha) {
            submitted = await dismissReviewForStaleHead(repo, prNumber, token, submitted.review, submitted.body);
          }
          const pendingDismissals = await reconcileReplacementSupersession(repo, prNumber, token, priorDecisive, submitted, normalized.evidenceComplete, task);
          writeJsonAtomic(recordPath, publicationRecord(task, identity, submitted.review, submitted.decision, previous, pendingDismissals));
          task.publication_state = submitted.staleAfterSubmit ? "published_review_dismissed_stale" : submitted.staleEvidence ? "published_review_stale_comment" : "publication_skipped_duplicate";
          task.publication_identity = identity;
          task.publication_review_id = submitted.review.id;
          task.publication_url = submitted.review.html_url;
          task.publication_decision = submitted.decision;
          clearPublicationError(task);
          return;
        }

        for (const pending of trustedReviews.filter((review) => String(review.state || "").toUpperCase() === "PENDING")) {
          await githubRequest("DELETE", `https://api.github.com/repos/${repo}/pulls/${prNumber}/reviews/${Number(pending.id)}`, token);
        }
        let publishedBody = `${safePublicationText(publicationReviewBody(task, result, normalized, previous, identity), 59_700)}\n\n${publicationMarker(trust, identity, task.created_at)}`;
        const reviewPayload: JsonObject = {body: publishedBody, commit_id: evidence.head_sha};
        if (normalized.inlineComments.length) reviewPayload.comments = normalized.inlineComments;
        let pendingReview: JsonObject;
        try {
          pendingReview = (await githubRequest("POST", `https://api.github.com/repos/${repo}/pulls/${prNumber}/reviews`, token, reviewPayload)) as JsonObject;
        } catch (error) {
          if (!normalized.inlineComments.length || !inlineLocationError(error)) throw error;
          publishedBody = safePublicationText(`${publishedBody}\n\n_Inline publication was unavailable; findings are included above._`);
          pendingReview = (await githubRequest("POST", `https://api.github.com/repos/${repo}/pulls/${prNumber}/reviews`, token, {
            body: publishedBody,
            commit_id: evidence.head_sha,
          })) as JsonObject;
        }
        pendingReview = {...pendingReview, body: publishedBody, state: pendingReview.state || "PENDING"};
        writeJsonAtomic(recordPath, publicationRecord(task, identity, pendingReview, normalized.decision, previous, priorDecisive, true));
        const submitted = await submitPendingReview(repo, prNumber, token, pendingReview, normalized.decision, String(evidence.head_sha || ""), publishedBody);
        task.publication_state = submitted.staleAfterSubmit ? "published_review_dismissed_stale" : submitted.staleEvidence ? "published_review_stale_comment" : "published_review";
        task.publication_identity = identity;
        task.publication_review_id = submitted.review.id;
        task.publication_url = submitted.review.html_url;
        task.publication_decision = submitted.decision;
        clearPublicationError(task);
        const pendingDismissals = await reconcileReplacementSupersession(repo, prNumber, token, priorDecisive, submitted, normalized.evidenceComplete, task);
        writeJsonAtomic(recordPath, publicationRecord(task, identity, submitted.review, submitted.decision, previous, pendingDismissals));
        return;
      }

      if (task.publication_identity === identity && task.publication_comment_id) {
        task.publication_state = "publication_skipped_duplicate";
        clearPublicationError(task);
        return;
      }
      const issueTrust = publicationTrust(config, task, `${repo}#issue:${Number(number)}`);
      const body = `${safePublicationText(publicationCommentBody(task, result, "Coven task result"), 59_700)}\n\n${publicationMarker(issueTrust, identity, task.created_at)}`;
      if (!task.publication_comment_id) {
        const comments = await githubRequestAllPages(`https://api.github.com/repos/${repo}/issues/${Number(number)}/comments`, token);
        const existing = publicationWithIdentity(comments, identity, issueTrust);
        if (existing) {
          task.publication_state = "publication_skipped_duplicate";
          task.publication_identity = identity;
          task.publication_url = existing.html_url;
          task.publication_comment_id = existing.id;
          clearPublicationError(task);
          return;
        }
      }
      const method = task.publication_comment_id ? "PATCH" : "POST";
      const url = task.publication_comment_id
        ? `https://api.github.com/repos/${repo}/issues/comments/${Number(task.publication_comment_id)}`
        : `https://api.github.com/repos/${repo}/issues/${Number(number)}/comments`;
      const response = (await githubRequest(method, url, token, {body})) as JsonObject;
      task.publication_state = method === "PATCH" ? "updated_comment" : "published_comment";
      task.publication_identity = identity;
      task.publication_url = response.html_url;
      task.publication_comment_id = response.id;
      clearPublicationError(task);
    } catch (error) {
      task.publication_state = "publication_failed";
      task.publication_error = redactTokenish(String((error as Error).stack || error));
    }
  } finally {
    releasePublicationLock(publicationLock);
  }
}

function publicationReviewBody(task: JsonObject, result: JsonObject, normalized: NormalizedReviewPublication, previous: JsonObject, identity: string): string {
  const renderedResult = normalized.evidenceComplete
    ? {...result, review: normalized.review}
    : {
        ...result,
        summary: "The runtime review output was downgraded because its publication evidence was incomplete or contradictory.",
        pr_body: "",
        review: normalized.review,
      };
  const body = publicationCommentBody(task, renderedResult, "Coven review");
  const additions: string[] = [];
  const previousUrl = previous.review_url || previous.html_url;
  if (previousUrl && previous.identity !== identity) additions.push(`This review supersedes [the prior covencat publication](${String(previousUrl)}).`);
  if (normalized.validationIssues.length) additions.push(`### Publication validation\n- ${normalized.validationIssues.join("\n- ")}\n\nEvidence was incomplete or contradictory, so this is a COMMENT review rather than an approval or change request.`);
  if (normalized.review.findings && Array.isArray(normalized.review.findings) && normalized.inlineComments.length < normalized.review.findings.length) additions.push("### Findings without valid inline locations\nThe structured findings above remain part of this review body because their file/line locations could not be safely attached to the current diff.");
  return [body, ...additions].join("\n\n");
}

function publicationCommentBody(task: JsonObject, result: JsonObject, heading = "Coven task result"): string {
  const status = result.status || "unknown";
  const summary = String(result.summary || "No summary returned.");
  const prBody = String(result.pr_body || "");
  const filesChanged = Array.isArray(result.files_changed) ? result.files_changed : [];
  const commits = Array.isArray(result.commits) ? result.commits : [];
  const taskId = String(task.task_id || "");
  const evidence = (task.review_evidence as JsonObject | undefined) || {};
  const review = (result.review as JsonObject | undefined) || {};
  const parts = [`## ${heading}`, "", `**Status:** ${status}`, "", summary.trim()];
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
  parts.push(...structuredReviewLines(review, task));
  parts.push(
    "",
    `**Files changed:** ${filesChanged.length}`,
    `**Commits:** ${commits.length}`,
    "",
    `_Task \`${taskId}\`._`,
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

function githubFileMarkdown(task: JsonObject, raw: JsonValue): string {
  const match = String(raw).match(/^(.*?)(?::(\d+))?$/);
  const path = repositoryPath(match?.[1]);
  const evidence = (task.review_evidence as JsonObject | undefined) || {};
  const ref = String(evidence.head_sha || "").trim();
  const repo = String(task.repository || "").trim();
  if (!path || !ref || !repo || !/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repo)) return `\`${String(raw)}\``;
  const encodedPath = path.split("/").map(encodeURIComponent).join("/");
  const anchor = match?.[2] ? `#L${match[2]}` : "";
  return `[\`${String(raw)}\`](https://github.com/${repo}/blob/${encodeURIComponent(ref)}/${encodedPath}${anchor})`;
}

function structuredReviewLines(review: JsonObject, task?: JsonObject): string[] {
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
    lines.push(`- Reviewed file list: ${reviewedFiles.slice(0, 20).map((path) => task ? githubFileMarkdown(task, path) : `\`${path}\``).join(", ")}`);
    if (reviewedFiles.length > 20) {
      lines.push("- Reviewed file list truncated after 20 entries.");
    }
  }
  const supportingFiles = Array.isArray(review.supporting_files) ? review.supporting_files : [];
  lines.push(`- Supporting files inspected: ${supportingFiles.length}`);
  if (supportingFiles.length) {
    lines.push(`- Supporting file list: ${supportingFiles.slice(0, 20).map((path) => task ? githubFileMarkdown(task, path) : `\`${path}\``).join(", ")}`);
    if (supportingFiles.length > 20) {
      lines.push("- Supporting file list truncated after 20 entries.");
    }
  }
  const findings = Array.isArray(review.findings) ? (review.findings as JsonObject[]) : [];
  lines.push(`- Findings: ${findings.length}`);
  findings.slice(0, 40).forEach((finding, index) => {
    let location = String(finding.file || "unknown file");
    if (finding.line !== undefined && finding.line !== null) {
      location = `${location}:${finding.line}`;
    }
    lines.push(`  ${index + 1}. \`${finding.severity || "unknown"}\` ${location} - ${finding.title || "Untitled finding"}`);
    if (finding.body) lines.push(`     - ${safePublicationText(String(finding.body), 700)}`);
    if (finding.recommendation) lines.push(`     - Suggested resolution: ${safePublicationText(String(finding.recommendation), 500)}`);
  });
  if (findings.length > 40) {
    const omitted = findings.length - 40;
    lines.push(`- ${omitted} additional finding${omitted === 1 ? " was" : "s were"} omitted because the GitHub review body is size-limited; inspect the persisted result artifact for the complete set.`);
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

export function sanitizedRuntimeEnvironment(source: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {};
  for (const key of [
    "PATH", "LANG", "LANGUAGE", "LC_ALL", "LC_CTYPE", "TZ",
    "TMPDIR", "TEMP", "TMP", "SystemRoot", "SYSTEMROOT", "WINDIR",
    "COMSPEC", "PATHEXT", "USERPROFILE",
  ]) {
    if (source[key] !== undefined) env[key] = source[key];
  }
  return env;
}

export function redactTokenish(text: string): string {
  if (!text) {
    return text;
  }
  return text
    .replace(/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g, "[redacted private key]")
    .replace(/\b(?:gh[pousr]_|github_pat_)[A-Za-z0-9_-]{6,}/g, "[redacted github token]")
    .replace(/\bsk-(?:proj-)?[A-Za-z0-9_-]{8,}/g, "[redacted OpenAI token]")
    .replace(/\bBearer\s+[^\s'\"]+/gi, "Bearer [redacted]")
    .replace(/\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g, "[redacted JWT]")
    .replace(/x-access-token:[^@\s'\"]+/gi, "x-access-token:[redacted]")
    .replace(/(https?:\/\/)[^/\s:@]+:[^@\s/]+@/gi, "$1[redacted]@");
}

function failTask(path: string, task: JsonObject, reason: string, detail: string): JsonObject {
  task.state = "failed";
  task.failure_category = reason;
  task.failure_detail = redactTokenish(String(detail)).slice(-4000);
  task.updated_at = utcNow();
  writeJsonAtomic(path, task);
  return task;
}
