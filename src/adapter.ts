import {createHash, createHmac, createSign, randomUUID, timingSafeEqual} from "node:crypto";
import {closeSync, constants as fsConstants, existsSync, fstatSync, lstatSync, mkdirSync, openSync, readdirSync, readFileSync, realpathSync, renameSync, rmSync, statSync, writeFileSync} from "node:fs";
import {homedir, hostname} from "node:os";
import {basename, dirname, isAbsolute, join, relative, resolve, sep} from "node:path";
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
  publicationSigningSecret: string;
  publicationVerificationSecrets: string[];
  covenCodeBin: string;
  covenCodeModel: string;
  maxReviewFixLoops: number;
  codexTokensPath: string;
  runtimeIsolation: string;
  bwrapBin: string;
  runtimeRootfs: string;
  runtimeNetwork: "none" | "shared";
  runtimeExternalIsolationVerified: boolean;
  revocationEventsVerified: boolean;
  hostGitBin: string;
  runtimeGitBin: string;
  runtimeShellBin: string;
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
  signal: string | null;
  timed_out: boolean;
  spawn_error: string;
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
    readonly retryAfterMs: number,
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
const REQUIRED_NATIVE_REVIEW_TRIGGERS = [
  "pull_request.synchronize",
  "pull_request.edited",
  "pull_request.reopened",
  "push",
] as const;
const MAX_GITHUB_RETRY_DELAY_MS = 24 * 60 * 60 * 1000;
const MAX_GENERIC_RETRY_DELAY_MS = 60 * 60 * 1000;

function lstatIfPresent(path: string): ReturnType<typeof lstatSync> | null {
  try {
    return lstatSync(path);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw error;
  }
}

function assertTrustedDirectory(path: string, label: string, requirePrivateOwnership = true): void {
  const entry = lstatIfPresent(path);
  if (!entry) throw new Error(`${label} does not exist`);
  if (entry.isSymbolicLink() || !entry.isDirectory()) {
    throw new Error(`${label} must be a real directory, not a symbolic link or another file type`);
  }
  if (realpathSync(path) !== resolve(path)) {
    throw new Error(`${label} must not traverse a symbolic-link ancestor`);
  }
  if (requirePrivateOwnership && typeof process.getuid === "function") {
    if (Number(entry.uid) !== process.getuid()) throw new Error(`${label} must be owned by the service user`);
    if ((Number(entry.mode) & 0o077) !== 0) throw new Error(`${label} must not grant group or world access`);
  }
}

function assertSafeDirectoryAncestors(path: string, label: string): void {
  let cursor = resolve(path);
  while (true) {
    const entry = lstatSync(cursor);
    if (entry.isSymbolicLink() || !entry.isDirectory()) throw new Error(`${label} ancestor must be a real directory: ${cursor}`);
    const writableByOthers = Number(entry.mode) & 0o022;
    const sticky = Number(entry.mode) & 0o1000;
    if (writableByOthers && !sticky) {
      throw new Error(`${label} must not be beneath a group- or world-writable non-sticky directory: ${cursor}`);
    }
    const parent = dirname(cursor);
    if (parent === cursor) break;
    cursor = parent;
  }
}

function ensureManagedDirectory(path: string, label: string): void {
  const target = resolve(path);
  const missing: string[] = [];
  let cursor = target;
  while (!lstatIfPresent(cursor)) {
    missing.push(cursor);
    const parent = dirname(cursor);
    if (parent === cursor) throw new Error(`Cannot locate an existing parent for ${label}`);
    cursor = parent;
  }
  assertTrustedDirectory(cursor, `${label} existing ancestor`, false);
  for (const directory of missing.reverse()) {
    try {
      mkdirSync(directory, {mode: 0o700});
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
    }
    assertTrustedDirectory(directory, label);
  }
  assertTrustedDirectory(target, label);
  assertSafeDirectoryAncestors(target, label);
}

function ensureManagedChildDirectory(parent: string, name: string, label: string): string {
  assertTrustedDirectory(parent, `${label} parent`);
  const path = join(parent, name);
  const entry = lstatIfPresent(path);
  if (!entry) mkdirSync(path, {mode: 0o700});
  assertTrustedDirectory(path, label);
  return path;
}

function createFreshChildDirectory(parent: string, name: string, label: string): string {
  assertTrustedDirectory(parent, `${label} parent`);
  const path = join(parent, name);
  if (lstatIfPresent(path)) throw new Error(`${label} already exists; refusing to reuse it`);
  mkdirSync(path, {mode: 0o700});
  assertTrustedDirectory(path, label);
  return path;
}

function createFreshTaskAttemptDirectory(root: string, taskId: string, attempt: number, label: string): string {
  if (!validRecordId(taskId)) throw new Error(`Invalid task ID for ${label}`);
  if (!Number.isSafeInteger(attempt) || attempt <= 0) throw new Error(`Invalid attempt number for ${label}`);
  const taskRoot = ensureManagedChildDirectory(root, taskId, `${label} task directory`);
  return createFreshChildDirectory(taskRoot, String(attempt), `${label} attempt directory`);
}

export function createConfig(env: NodeJS.ProcessEnv = process.env, rootDir = process.cwd()): AdapterConfig {
  const stateDir = resolve(env.COVEN_GITHUB_STATE_DIR || join(rootDir, "coven-github-state"));
  const webhookSecret = (env.GITHUB_WEBHOOK_SECRET || env.WEBHOOK_SECRET || "").trim();
  const publicationSigningSecret = (env.COVEN_PUBLICATION_SIGNING_SECRET || webhookSecret).trim();
  const previousPublicationSecrets = (env.COVEN_PUBLICATION_PREVIOUS_SIGNING_SECRETS || "")
    .split(",")
    .map((secret) => secret.trim())
    .filter(Boolean);
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
    webhookSecret,
    publicationSigningSecret,
    publicationVerificationSecrets: [...new Set([publicationSigningSecret, ...previousPublicationSecrets].filter(Boolean))],
    covenCodeBin: (env.COVEN_CODE_BIN || "coven-code").trim() || "coven-code",
    covenCodeModel: (env.COVEN_CODE_MODEL || "gpt-5.5").trim(),
    maxReviewFixLoops: envInt(env.COVEN_REVIEW_FIX_LOOPS, 0, 0, 5),
    codexTokensPath: configuredCodexTokensPath(env),
    runtimeIsolation: (env.COVEN_RUNTIME_ISOLATION || "disabled").trim().toLowerCase(),
    bwrapBin: resolve(env.COVEN_BWRAP_BIN || "/usr/bin/bwrap"),
    runtimeRootfs: env.COVEN_RUNTIME_ROOTFS ? resolve(env.COVEN_RUNTIME_ROOTFS) : "",
    runtimeNetwork: (env.COVEN_RUNTIME_NETWORK || "none").trim().toLowerCase() === "shared" ? "shared" : "none",
    runtimeExternalIsolationVerified: (env.COVEN_RUNTIME_EXTERNAL_ISOLATION || "").trim() === "network-egress-and-resource-limits-verified",
    revocationEventsVerified: (env.COVEN_GITHUB_REVOCATION_EVENTS || "").trim() === "pull-request-and-push-verified",
    hostGitBin: resolve(env.COVEN_HOST_GIT_BIN || "/usr/bin/git"),
    runtimeGitBin: (env.COVEN_RUNTIME_GIT_BIN || "/usr/bin/git").trim(),
    runtimeShellBin: (env.COVEN_RUNTIME_SHELL_BIN || "/bin/sh").trim(),
    maxWebhookBodyBytes: MAX_WEBHOOK_BODY_BYTES,
    demoMode: ["1", "true", "yes"].includes((env.COVEN_GITHUB_DEMO_MODE || "").trim().toLowerCase()),
  };

  ensureManagedDirectory(config.stateDir, "COVEN_GITHUB_STATE_DIR");
  for (const [directory, label] of [
    [config.deliveriesDir, "delivery state directory"],
    [config.tasksDir, "task state directory"],
    [config.publicationsDir, "publication state directory"],
    [config.workspacesDir, "workspace state directory"],
    [config.attemptsDir, "attempt state directory"],
  ] as Array<[string, string]>) {
    ensureManagedChildDirectory(config.stateDir, basename(directory), label);
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

function readStateJson<T extends JsonValue>(path: string, fallback: T): T {
  let descriptor: number | undefined;
  try {
    descriptor = openSync(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW | fsConstants.O_NONBLOCK);
    const details = fstatSync(descriptor);
    if (!details.isFile()) throw new Error(`Persisted state is not a regular file: ${path}`);
    if (details.size > MAX_WEBHOOK_BODY_BYTES) throw new Error(`Persisted state is too large: ${path}`);
    return JSON.parse(readFileSync(descriptor, "utf8")) as T;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return fallback;
    throw error;
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
  }
}

function writeJsonAtomic(path: string, value: JsonValue): void {
  mkdirSync(dirname(path), {recursive: true});
  const tmpName = join(dirname(path), `${basename(path)}.${randomUUID()}.tmp`);
  try {
    writeFileSync(tmpName, `${stableStringify(value)}\n`, {encoding: "utf8", flag: "wx", mode: 0o600});
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
    const retryAfter = String(response.headers.get("retry-after") || "").trim();
    const retryAfterSeconds = /^\d+$/.test(retryAfter) ? Number(retryAfter) * 1000 : 0;
    const retryAfterDate = retryAfter && !retryAfterSeconds ? Date.parse(retryAfter) - Date.now() : 0;
    const rateLimitReset = Number(response.headers.get("x-ratelimit-reset") || 0) * 1000 - Date.now();
    const retryAfterMs = Math.max(0, retryAfterSeconds, Number.isFinite(retryAfterDate) ? retryAfterDate : 0, Number.isFinite(rateLimitReset) ? rateLimitReset : 0);
    throw new GithubApiError(response.status, raw, Math.min(MAX_GITHUB_RETRY_DELAY_MS, retryAfterMs), method, url);
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

async function installationToken(config: AdapterConfig, installationId: JsonValue | undefined, request: JsonObject): Promise<string> {
  const response = (await githubRequest(
    "POST",
    `https://api.github.com/app/installations/${installationId}/access_tokens`,
    githubAppJwt(config),
    request,
  )) as JsonObject;
  const token = response.token;
  if (typeof token !== "string" || !token) {
    throw new Error("GitHub installation token response did not include token");
  }
  return token;
}

function repositoryInstallationTokenRequest(repositoryId: JsonValue | undefined, permissions: JsonObject): JsonObject {
  const id = Number(repositoryId);
  if (!Number.isSafeInteger(id) || id <= 0) {
    throw new Error("A valid repository ID is required for a scoped installation token");
  }
  return {
    repository_ids: [id],
    permissions,
  };
}

export function runtimeInstallationTokenRequest(repositoryId: JsonValue | undefined): JsonObject {
  return repositoryInstallationTokenRequest(repositoryId, {contents: "read"});
}

export function reviewContextInstallationTokenRequest(repositoryId: JsonValue | undefined): JsonObject {
  return repositoryInstallationTokenRequest(repositoryId, {contents: "read", pull_requests: "read"});
}

export function publicationInstallationTokenRequest(repositoryId: JsonValue | undefined): JsonObject {
  return repositoryInstallationTokenRequest(repositoryId, {issues: "write", pull_requests: "write"});
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
  if (!validRecordId(deliveryId)) throw new Error("Invalid GitHub delivery ID");
  return join(config.deliveriesDir, `${deliveryId}.json`);
}

function taskPath(config: AdapterConfig, taskId: string): string {
  if (!validRecordId(taskId)) throw new Error("Invalid task ID");
  return join(config.tasksDir, `${taskId}.json`);
}

function validRecordId(value: string): boolean {
  return /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/.test(value);
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
  if (method === "GET" && request.path === "/readyz") {
    const issue = adapterReadinessIssue(config);
    return issue
      ? {status: 503, body: {ok: false, runtime_ready: false, error: issue}}
      : {status: 200, body: {ok: true, runtime_ready: true}};
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
  if (!validRecordId(deliveryId)) {
    return {status: 400, body: {error: "invalid delivery id"}};
  }
  const routed = await routeDelivery(config, eventName, deliveryId, payload, debug);
  return {
    status: routed.reason === "native_review_policy_unsafe" ? 503 : routed.reason === "delivery_task_conflict" ? 409 : 200,
    body: routed,
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

export function nativeReviewPolicyIssue(policy: JsonObject): string | null {
  const publication = (policy.publication as JsonObject | undefined) || {};
  if ((publication.mode || "record_only") !== "comment") return null;
  const enabled = new Set((Array.isArray(policy.enabled_triggers) ? policy.enabled_triggers : []).map(String));
  const missing = REQUIRED_NATIVE_REVIEW_TRIGGERS.filter((trigger) => !enabled.has(trigger));
  return missing.length
    ? `Native PR publication requires revocation triggers: ${missing.join(", ")}`
    : null;
}

function nativeReviewReadinessIssue(config: AdapterConfig, policy: JsonObject): string | null {
  const policyIssue = nativeReviewPolicyIssue(policy);
  if (policyIssue) return policyIssue;
  const publication = (policy.publication as JsonObject | undefined) || {};
  if (!config.demoMode && (publication.mode || "record_only") === "comment" && !config.revocationEventsVerified) {
    return "COVEN_GITHUB_REVOCATION_EVENTS must confirm that the installed GitHub App receives pull_request and push events";
  }
  return null;
}

export function adapterReadinessIssue(config: AdapterConfig): string | null {
  if (!config.demoMode) {
    const isolationIssue = runtimeIsolationIssue(config);
    if (isolationIssue) return isolationIssue;
  }
  if (!existsSync(config.policyPath)) return `COVEN_GITHUB_POLICY_PATH does not exist: ${config.policyPath}`;
  const policy = readJson<JsonObject>(config.policyPath, DEFAULT_POLICY);
  const installations = (policy.installations as JsonObject | undefined) || {};
  for (const installation of Object.values(installations)) {
    if (!installation || typeof installation !== "object" || Array.isArray(installation)) continue;
    const repositories = (((installation as JsonObject).repositories as JsonObject | undefined) || {});
    for (const route of Object.values(repositories)) {
      if (!route || typeof route !== "object" || Array.isArray(route)) continue;
      const issue = nativeReviewReadinessIssue(config, route as JsonObject);
      if (issue) return issue;
    }
  }
  return null;
}

function eventTriggerKey(eventName: string, payload: JsonObject): string {
  const action = String(payload.action || "").trim();
  return action ? `${eventName}.${action}` : eventName;
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
  if (!familiar && eventName !== "pull_request" && eventName !== "push") {
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
    if (action === "assigned") {
      const assignee = (payload.assignee as JsonObject | undefined) || (issue.assignee as JsonObject | undefined) || {};
      const botUsernames = new Set((Array.isArray(policy.bot_usernames) ? policy.bot_usernames : []).map((name) => String(name).toLowerCase()));
      if (botUsernames.size && !botUsernames.has(String(assignee.login || "").toLowerCase())) {
        return ignored(base, "issue_assignment_not_for_bot");
      }
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
      trigger: "pull_request_revision",
      target: {
        kind: "pull_request",
        pr_number: Number(pullRequest.number || 0),
        head_sha: head.sha,
        head_ref: head.ref,
        base_sha: baseRef.sha,
        base_ref: baseRef.ref,
      },
      task: {
        kind: "reconcile_pull_request_revision",
        action: payload.action,
        pr_number: Number(pullRequest.number || 0),
        head_sha: head.sha,
        base_sha: baseRef.sha,
      },
      issue_refs: [...((base.issue_refs as JsonValue[]) || []), "OpenCoven/coven-github#10"],
    });
    return base;
  }

  if (eventName === "push") {
    const ref = String(payload.ref || "");
    if (!ref.startsWith("refs/heads/") || ref.length <= "refs/heads/".length) {
      return ignored(base, "push_without_branch_ref");
    }
    Object.assign(base, {
      trigger: "base_branch_revision",
      target: {
        ref: payload.ref,
        before: payload.before,
        after: payload.after,
        commit_count: Array.isArray(payload.commits) ? payload.commits.length : 0,
      },
      task: {
        kind: "reconcile_base_branch_push",
        base_ref: ref.slice("refs/heads/".length),
        before: payload.before,
        after: payload.after,
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
  const lock = await acquirePublicationLock(config, `delivery:${deliveryId}`);
  try {
    return await routeClaimedDelivery(config, eventName, deliveryId, payload, debug);
  } finally {
    releasePublicationLock(lock);
  }
}

async function routeClaimedDelivery(
  config: AdapterConfig,
  eventName: string,
  deliveryId: string,
  payload: JsonObject,
  debug: (message: string) => void,
): Promise<JsonObject> {
  const deliveryFile = deliveryPath(config, deliveryId);
  if (existsSync(deliveryFile)) {
    const existing = readStateJson<JsonObject>(deliveryFile, {});
    const existingTaskId = String(existing.task_id || "");
    let action = "duplicate_ignored";
    let task = existingTaskId ? readStateJson<JsonObject>(taskPath(config, existingTaskId), {}) : {};
    if (existingTaskId && (["queued", "running"].includes(String(task.state || "")) || revisionReconciliationRecoveryEligible(task))) {
      action = "duplicate_task_queued";
    } else if (existingTaskId && publicationRecoveryEligible(task)) {
      action = "duplicate_retry_queued";
    }
    return {
      ok: true,
      action,
      delivery_id: deliveryId,
      task_id: existing.task_id,
      state: task.state || existing.state,
      publication_state: task.publication_state || existing.publication_state,
      queued: action === "duplicate_retry_queued" || action === "duplicate_task_queued",
    };
  }

  const delivery = deliveryRecord(deliveryId, eventName, payload);
  const orphanTaskFile = taskPath(config, deliveryId);
  if (existsSync(orphanTaskFile)) {
    const task = readStateJson<JsonObject>(orphanTaskFile, {});
    if (task.delivery_id !== deliveryId || task.delivery_payload_hash !== delivery.payload_hash) {
      return {
        ok: false,
        action: "conflict",
        delivery_id: deliveryId,
        task_id: task.task_id,
        reason: "delivery_task_conflict",
        error: "A task exists for this delivery ID but cannot be matched to the signed payload; refusing to overwrite it.",
      };
    }
    delivery.task_id = task.task_id;
    delivery.state = task.state;
    delivery.routing_result = task.ignored_reason || "recovered_orphan_task";
    writeJsonAtomic(deliveryFile, delivery);
    let action = "duplicate_ignored";
    if (["queued", "running"].includes(String(task.state || "")) || revisionReconciliationRecoveryEligible(task)) {
      action = "duplicate_task_queued";
    } else if (publicationRecoveryEligible(task)) {
      action = "duplicate_retry_queued";
    }
    return {
      ok: true,
      action,
      delivery_id: deliveryId,
      task_id: task.task_id,
      state: task.state,
      publication_state: task.publication_state,
      queued: action === "duplicate_retry_queued" || action === "duplicate_task_queued",
      recovered_orphan_task: true,
    };
  }
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

  const safetyIssue = nativeReviewReadinessIssue(config, policy);
  if (safetyIssue) {
    return {
      ok: false,
      action: "retry",
      delivery_id: deliveryId,
      reason: "native_review_policy_unsafe",
      error: safetyIssue,
    };
  }

  const trigger = eventTriggerKey(eventName, payload);
  const enabledTriggers = new Set((Array.isArray(policy.enabled_triggers) ? policy.enabled_triggers : []).map(String));
  if (!enabledTriggers.has(trigger)) {
    delivery.state = "ignored";
    delivery.routing_result = "trigger_not_enabled";
    delivery.installation_id = installationId;
    delivery.repository_id = repoId;
    writeJsonAtomic(deliveryFile, delivery);
    return {
      ok: true,
      action: "ignored",
      delivery_id: deliveryId,
      reason: "trigger_not_enabled",
      trigger,
    };
  }

  const task = buildTaskFromEvent(eventName, deliveryId, payload, policy);
  task.delivery_payload_hash = delivery.payload_hash;
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

  if (task.state === "queued" && config.demoMode) {
    try {
      await runTask(config, String(task.task_id));
    } catch (error) {
      debug(`COVEN GITHUB TASK RUN FAIL task_id=${task.task_id} ${String((error as Error).stack || error)}`);
    }
  }

  const persistedTask = readStateJson<JsonObject>(taskPath(config, String(task.task_id)), task);

  return {
    ok: true,
    action: task.state !== "ignored" ? "accepted" : "ignored",
    delivery_id: deliveryId,
    task_id: task.task_id,
    state: persistedTask.state,
    reason: task.ignored_reason,
    queued: persistedTask.state === "queued",
  };
}

function runCommand(args: string[], cwd?: string, env?: NodeJS.ProcessEnv, timeoutSeconds = 300): CommandResult {
  const proc = spawnSync(args[0], args.slice(1), {
    cwd,
    env,
    encoding: "utf8",
    timeout: timeoutSeconds * 1000,
    killSignal: "SIGKILL",
    maxBuffer: 20 * 1024 * 1024,
  });
  return {
    args,
    returncode: proc.status ?? 125,
    stdout: String(proc.stdout || "").slice(-8000),
    stderr: `${String(proc.stderr || "")}${proc.error ? String(proc.error.message || proc.error) : ""}`.slice(-8000),
    signal: proc.signal || null,
    timed_out: (proc.error as NodeJS.ErrnoException | undefined)?.code === "ETIMEDOUT",
    spawn_error: proc.error ? String(proc.error.message || proc.error) : "",
  };
}

const MAX_RUNTIME_RESULT_BYTES = 2 * 1024 * 1024;

function pathContains(root: string, candidate: string): boolean {
  const path = relative(root, candidate);
  return path === "" || (!path.startsWith(`..${sep}`) && path !== ".." && !isAbsolute(path));
}

function runtimeRootfsPath(config: AdapterConfig, sandboxPath: string): string {
  if (!isAbsolute(sandboxPath)) {
    throw new Error(`Sandbox executable path must be absolute: ${sandboxPath || "<empty>"}`);
  }
  const candidate = resolve(config.runtimeRootfs, `.${sandboxPath}`);
  if (!pathContains(resolve(config.runtimeRootfs), candidate)) {
    throw new Error(`Sandbox executable escapes COVEN_RUNTIME_ROOTFS: ${sandboxPath}`);
  }
  return candidate;
}

function sameFilesystemObject(left: string, right: string): boolean {
  const leftStat = statSync(left);
  const rightStat = statSync(right);
  return leftStat.dev === rightStat.dev && leftStat.ino === rightStat.ino;
}

function decodeMountInfoPath(value: string): string {
  return value.replace(/\\([0-7]{3})/g, (_match, octal: string) => String.fromCharCode(Number.parseInt(octal, 8)));
}

function rootfsExposureIssue(config: AdapterConfig, rootfs: string): string | null {
  const protectedPaths = [
    config.rootDir,
    config.stateDir,
    config.policyPath,
    config.privateKeyPath,
    dirname(config.privateKeyPath),
    config.codexTokensPath,
    dirname(config.codexTokensPath),
    homedir(),
  ].filter((path) => existsSync(path)).map((path) => realpathSync(path));
  for (const path of protectedPaths) {
    let aliasesProtectedAncestor = false;
    for (let ancestor = path; ; ancestor = dirname(ancestor)) {
      if (sameFilesystemObject(rootfs, ancestor)) {
        aliasesProtectedAncestor = true;
        break;
      }
      const parent = dirname(ancestor);
      if (parent === ancestor) break;
    }
    if (pathContains(rootfs, path) || aliasesProtectedAncestor) {
      return "COVEN_RUNTIME_ROOTFS aliases or contains an adapter, state, policy, key, token, or parent-home path";
    }
    const mapped = runtimeRootfsPath(config, path);
    if (existsSync(mapped)) {
      return `COVEN_RUNTIME_ROOTFS contains a protected host path at ${path}`;
    }
  }
  const mountInfoPath = "/proc/self/mountinfo";
  if (!existsSync(mountInfoPath)) {
    return "Cannot verify COVEN_RUNTIME_ROOTFS mount topology without /proc/self/mountinfo";
  }
  for (const line of readFileSync(mountInfoPath, "utf8").split("\n")) {
    if (!line) continue;
    const fields = line.split(" ");
    if (fields.length < 5) continue;
    const mountPoint = decodeMountInfoPath(fields[4]);
    if (mountPoint !== rootfs && pathContains(rootfs, mountPoint)) {
      return `COVEN_RUNTIME_ROOTFS contains nested mount point ${mountPoint}`;
    }
  }
  return null;
}

export function runtimeIsolationIssue(config: AdapterConfig): string | null {
  if (config.runtimeIsolation !== "bwrap") {
    return config.runtimeIsolation === "disabled"
      ? "COVEN_RUNTIME_ISOLATION is disabled; configure a verified bwrap rootfs before running real tasks"
      : `Unsupported COVEN_RUNTIME_ISOLATION value: ${config.runtimeIsolation}`;
  }
  if (!config.runtimeExternalIsolationVerified) {
    return "COVEN_RUNTIME_EXTERNAL_ISOLATION must confirm externally enforced network-egress and CPU, memory, PID, and disk limits";
  }
  if (!isAbsolute(config.bwrapBin) || !existsSync(config.bwrapBin)) {
    return `COVEN_BWRAP_BIN is not an available absolute path: ${config.bwrapBin}`;
  }
  try {
    const binary = statSync(config.bwrapBin);
    if (!binary.isFile() || !(binary.mode & 0o111)) {
      return `COVEN_BWRAP_BIN is not executable: ${config.bwrapBin}`;
    }
    if (binary.uid !== 0 || (binary.mode & 0o022) !== 0) {
      return `COVEN_BWRAP_BIN must be root-owned and not group/world writable: ${config.bwrapBin}`;
    }
  } catch (error) {
    return `COVEN_BWRAP_BIN could not be inspected: ${String((error as Error).message || error)}`;
  }
  try {
    const hostGit = statSync(config.hostGitBin);
    if (!isAbsolute(config.hostGitBin) || !hostGit.isFile() || !(hostGit.mode & 0o111) || hostGit.uid !== 0 || (hostGit.mode & 0o022) !== 0) {
      return `COVEN_HOST_GIT_BIN must be an absolute, root-owned executable that is not group/world writable: ${config.hostGitBin}`;
    }
  } catch {
    return `COVEN_HOST_GIT_BIN is not available: ${config.hostGitBin}`;
  }
  if (!config.runtimeRootfs || !isAbsolute(config.runtimeRootfs) || !existsSync(config.runtimeRootfs)) {
    return "COVEN_RUNTIME_ROOTFS must name an existing absolute directory";
  }
  try {
    const rootfs = realpathSync(config.runtimeRootfs);
    if (!statSync(rootfs).isDirectory() || rootfs === sep) {
      return "COVEN_RUNTIME_ROOTFS must be a dedicated directory, not the host root";
    }
    const exposureIssue = rootfsExposureIssue(config, rootfs);
    if (exposureIssue) return exposureIssue;
  } catch (error) {
    return `COVEN_RUNTIME_ROOTFS could not be inspected: ${String((error as Error).message || error)}`;
  }
  for (const executable of [config.covenCodeBin, config.runtimeGitBin, config.runtimeShellBin, "/bin/true"]) {
    if (["/workspace", "/run", "/tmp", "/home", "/proc", "/dev"].some((mount) => executable === mount || executable.startsWith(`${mount}/`))) {
      return `Sandbox executable path is shadowed by a writable or synthetic mount: ${executable}`;
    }
    try {
      const hostPath = runtimeRootfsPath(config, executable);
      const file = statSync(hostPath);
      if (!file.isFile() || !(file.mode & 0o111)) {
        return `Sandbox executable is missing or not executable: ${executable}`;
      }
    } catch {
      return `Sandbox executable is missing or not executable: ${executable}`;
    }
  }
  return null;
}

interface SandboxMounts {
  workspace: string;
  inputDir: string;
  outputDir: string;
}

export function runtimeSandboxArgs(
  config: AdapterConfig,
  mounts: SandboxMounts,
  command: string[],
  network: "none" | "shared" = config.runtimeNetwork,
): string[] {
  if (!command.length || !isAbsolute(command[0])) {
    throw new Error("Sandbox command must start with an absolute executable path");
  }
  const allowedExecutables = new Set([config.covenCodeBin, config.runtimeGitBin, config.runtimeShellBin, "/bin/true"]);
  if (!allowedExecutables.has(command[0])) {
    throw new Error(`Sandbox command is not an approved rootfs executable: ${command[0]}`);
  }
  const rootfs = realpathSync(config.runtimeRootfs);
  const workspace = realpathSync(mounts.workspace);
  const inputDir = realpathSync(mounts.inputDir);
  const outputDir = realpathSync(mounts.outputDir);
  const exposureIssue = rootfsExposureIssue(config, rootfs);
  if (exposureIssue) throw new Error(exposureIssue);
  const workspacesRoot = realpathSync(config.workspacesDir);
  const attemptsRoot = realpathSync(config.attemptsDir);
  if (!pathContains(workspacesRoot, workspace)) {
    throw new Error("Sandbox workspace mount must stay inside COVEN_GITHUB_STATE_DIR/workspaces");
  }
  if (!pathContains(attemptsRoot, inputDir) || !pathContains(attemptsRoot, outputDir)) {
    throw new Error("Sandbox input and output mounts must stay inside COVEN_GITHUB_STATE_DIR/attempts");
  }
  if (pathContains(inputDir, workspace) || pathContains(outputDir, workspace) || pathContains(workspace, inputDir) || pathContains(workspace, outputDir)) {
    throw new Error("Sandbox input, output, and workspace mounts must not overlap");
  }

  const args = [
    config.bwrapBin,
    "--die-with-parent",
    "--new-session",
    "--unshare-user",
    "--unshare-pid",
    "--unshare-ipc",
    "--unshare-uts",
    "--unshare-cgroup-try",
    "--cap-drop", "ALL",
    "--ro-bind", rootfs, "/",
    "--proc", "/proc",
    "--dev", "/dev",
    "--tmpfs", "/tmp",
    "--tmpfs", "/home",
    "--dir", "/home/coven",
    "--tmpfs", "/run",
    "--dir", "/run/coven",
    "--dir", "/run/coven/input",
    "--dir", "/run/coven/output",
    "--dir", "/workspace",
    "--ro-bind", inputDir, "/run/coven/input",
    "--bind", workspace, "/workspace",
    "--bind", outputDir, "/run/coven/output",
  ];
  const gitDir = join(workspace, ".git");
  if (existsSync(gitDir) && statSync(gitDir).isDirectory()) {
    args.push("--ro-bind", realpathSync(gitDir), "/workspace/.git");
  }
  if (network === "none") args.push("--unshare-net");
  args.push(
    "--chdir", "/workspace",
    "--setenv", "HOME", "/home/coven",
    "--setenv", "TMPDIR", "/tmp",
    "--setenv", "PATH", "/usr/local/bin:/usr/bin:/bin",
    "--",
    ...command,
  );
  return args;
}

function runSandboxedCommand(
  config: AdapterConfig,
  mounts: SandboxMounts,
  command: string[],
  env: NodeJS.ProcessEnv,
  timeoutSeconds: number,
  network: "none" | "shared" = config.runtimeNetwork,
): CommandResult {
  return runCommand(runtimeSandboxArgs(config, mounts, command, network), undefined, env, timeoutSeconds);
}

export function readBoundedRuntimeResult(path: string): JsonObject {
  let descriptor: number | undefined;
  try {
    descriptor = openSync(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW | fsConstants.O_NONBLOCK);
    const details = fstatSync(descriptor);
    if (!details.isFile()) throw new Error("runtime result is not a regular file");
    if (details.size > MAX_RUNTIME_RESULT_BYTES) {
      throw new Error(`runtime result exceeds ${MAX_RUNTIME_RESULT_BYTES} bytes`);
    }
    const parsed = JSON.parse(readFileSync(descriptor, "utf8")) as JsonValue;
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      throw new Error("runtime result is not a JSON object");
    }
    return parsed as JsonObject;
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
  }
}

function writeAskpass(workDir: string): string {
  const script = join(workDir, "git-askpass.sh");
  writeFileSync(script, "#!/bin/sh\nprintf '%s\\n' \"$COVEN_GIT_TOKEN\"\n", {encoding: "utf8", mode: 0o700});
  return script;
}

export function probeRuntimeIsolation(config: AdapterConfig, attemptDir: string): string | null {
  assertTrustedDirectory(attemptDir, "runtime-isolation attempt directory");
  const probeDir = createFreshChildDirectory(attemptDir, "sandbox-probe", "runtime-isolation probe directory");
  const probeRoot = ensureManagedChildDirectory(config.workspacesDir, ".sandbox-probes", "runtime-isolation probe workspace root");
  const workspace = createFreshChildDirectory(
    probeRoot,
    `${sha256(attemptDir).slice(0, 24)}-${randomUUID()}`,
    "runtime-isolation probe workspace",
  );
  const inputDir = createFreshChildDirectory(probeDir, "input", "runtime-isolation probe input");
  const outputDir = createFreshChildDirectory(probeDir, "output", "runtime-isolation probe output");
  try {
    const markerPath = join(inputDir, "read-only-marker");
    writeFileSync(markerPath, "unchanged\n", "utf8");
    const probe = runSandboxedCommand(
      config,
      {workspace, inputDir, outputDir},
      [
        config.runtimeShellBin,
        "-c",
        [
          "set -eu",
          "IFS= read -r marker < /run/coven/input/read-only-marker",
          "test \"$marker\" = unchanged",
          "if printf tampered > /run/coven/input/read-only-marker 2>/dev/null; then exit 21; fi",
          "printf workspace-ok > /workspace/probe",
          "printf output-ok > /run/coven/output/probe",
          "test ! -e /run/coven/host-state",
        ].join("\n"),
      ],
      {
        PATH: "/usr/local/bin:/usr/bin:/bin",
        HOME: "/home/coven",
        TMPDIR: "/tmp",
      },
      30,
      "none",
    );
    writeJsonAtomic(join(probeDir, "probe.json"), redactedCommandResult(probe));
    if (probe.returncode !== 0) {
      return `bubblewrap isolation probe failed: ${probe.stderr || `exit ${probe.returncode}`}`;
    }
    if (readFileSync(markerPath, "utf8") !== "unchanged\n") {
      return "bubblewrap isolation probe modified a read-only input";
    }
    if (readFileSync(join(workspace, "probe"), "utf8") !== "workspace-ok"
      || readFileSync(join(outputDir, "probe"), "utf8") !== "output-ok") {
      return "bubblewrap isolation probe could not write only to the permitted mounts";
    }
    return null;
  } finally {
    rmSync(workspace, {recursive: true, force: true});
  }
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
  const inputDir = join(attemptDir, `runtime-input${suffix}`);
  const outputDir = join(attemptDir, `runtime-output${suffix}`);
  mkdirSync(inputDir, {recursive: true});
  mkdirSync(outputDir, {recursive: true});
  const briefPath = join(inputDir, `session-brief${suffix}.json`);
  const resultPath = join(outputDir, `result${suffix}.json`);
  const runPath = join(attemptDir, `run${suffix}.json`);
  const sandboxBriefPath = `/run/coven/input/session-brief${suffix}.json`;
  const sandboxResultPath = `/run/coven/output/result${suffix}.json`;

  writeJsonAtomic(briefPath, sessionBrief(task, "/workspace", reviewContext, extraAuditInstruction));
  const run = runSandboxedCommand(
    config,
    {workspace, inputDir, outputDir},
    [
      config.covenCodeBin,
      "--headless",
      "--hosted-review",
      "--provider",
      "codex",
      "--model",
      config.covenCodeModel,
      "--context",
      sandboxBriefPath,
      "--output",
      sandboxResultPath,
    ],
    env,
    1800,
    config.runtimeNetwork,
  );
  writeJsonAtomic(runPath, redactedCommandResult(run));
  let result: JsonObject | null = null;
  const acceptableExit = [0, 1, 3].includes(run.returncode) && !run.signal && !run.timed_out && !run.spawn_error;
  if (existsSync(resultPath) && acceptableExit) {
    try {
      result = readBoundedRuntimeResult(resultPath);
    } catch (error) {
      run.returncode = run.returncode || 1;
      run.stderr = `${run.stderr}\nRejected runtime result: ${String((error as Error).message || error)}`.slice(-8000);
      writeJsonAtomic(runPath, redactedCommandResult(run));
    }
  } else if (existsSync(resultPath)) {
    run.stderr = `${run.stderr}\nRejected runtime result because the sandbox did not complete normally.`.slice(-8000);
    writeJsonAtomic(runPath, redactedCommandResult(run));
  }
  return {
    cycle,
    brief_path: briefPath,
    result_path: resultPath,
    run_path: runPath,
    run,
    result,
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

export async function runTask(config: AdapterConfig, taskId: string): Promise<JsonObject> {
  const lock = await acquirePublicationLock(config, `execution:${taskId}`);
  try {
    const path = taskPath(config, taskId);
    const task = readStateJson<JsonObject>(path, {});
    if (publicationRecoveryEligible(task)) return resumeTaskPublication(config, taskId);
    if (revisionReconciliationRecoveryEligible(task)) {
      if (!retryDeadlineReached(task)) return task;
      task.state = "queued";
      delete task.retry_not_before;
      task.updated_at = utcNow();
      writeJsonAtomic(path, task);
    }
    if (task.state === "running") {
      task.state = "queued";
      task.recovered_from_interrupted_worker = true;
      task.updated_at = utcNow();
      writeJsonAtomic(path, task);
    }
    return runTaskUnlocked(config, taskId);
  } finally {
    releasePublicationLock(lock);
  }
}

async function runTaskUnlocked(config: AdapterConfig, taskId: string): Promise<JsonObject> {
  const path = taskPath(config, taskId);
  const task = readStateJson<JsonObject>(path, {});
  if (task.state !== "queued") {
    return task;
  }

  if (["reconcile_pull_request_revision", "reconcile_base_branch_push"].includes(String(((task.task as JsonObject | undefined) || {}).kind || ""))) {
    return reconcilePullRequestRevisionTask(config, path, task);
  }

  if (!config.demoMode) {
    const configurationIssue = runtimeIsolationIssue(config);
    if (configurationIssue) {
      return blockTask(path, task, "runtime_isolation_unavailable", configurationIssue);
    }
  }

  const nextAttempt = Number(task.attempts || 0) + 1;
  task.state = "running";
  task.attempts = nextAttempt;
  task.updated_at = utcNow();
  writeJsonAtomic(path, task);
  let attemptDir: string;
  let workspaceAttemptDir: string;
  try {
    attemptDir = createFreshTaskAttemptDirectory(config.attemptsDir, taskId, nextAttempt, "task artifact");
    workspaceAttemptDir = createFreshTaskAttemptDirectory(config.workspacesDir, taskId, nextAttempt, "task workspace");
  } catch (error) {
    return blockTask(path, task, "state_storage_untrusted", String((error as Error).message || error));
  }
  if (!config.demoMode) {
    try {
      const probeIssue = probeRuntimeIsolation(config, attemptDir);
      if (probeIssue) {
        return blockTask(path, task, "runtime_isolation_unavailable", probeIssue);
      }
    } catch (error) {
      return blockTask(path, task, "runtime_isolation_unavailable", String((error as Error).stack || error));
    }
    task.runtime_isolation = {
      mode: "bwrap",
      verified: true,
      verified_at: utcNow(),
      network: config.runtimeNetwork,
    };
  }

  const workspace = join(workspaceAttemptDir, "repo");

  try {
    if (config.demoMode) {
      return completeDemoTask(path, task, workspace, attemptDir);
    }

    if (lstatIfPresent(workspace)) {
      return failTask(path, task, "workspace_untrusted", "Fresh per-attempt workspace already exists; refusing host Git execution");
    }
    task.workspace_path = workspace;
    writeJsonAtomic(path, task);
    const gitToken = await installationToken(
      config,
      task.installation_id,
      runtimeInstallationTokenRequest(task.repository_id),
    );
    const askpass = writeAskpass(attemptDir);
    const gitHome = join(attemptDir, "git-home");
    mkdirSync(gitHome, {recursive: true});
    const gitEnv: NodeJS.ProcessEnv = {
      ...sanitizedRuntimeEnvironment(process.env),
      GIT_ASKPASS: askpass,
      GIT_TERMINAL_PROMPT: "0",
      GIT_CONFIG_GLOBAL: "/dev/null",
      GIT_CONFIG_NOSYSTEM: "1",
      COVEN_GIT_TOKEN: gitToken,
      HOME: gitHome,
    };
    const codexAccessToken = loadCodexAccessToken(config);
    if (!codexAccessToken) {
      return failTask(path, task, "codex_auth_missing", `Missing Codex access token at ${config.codexTokensPath}`);
    }
    const runtimeEnv = runtimeProcessEnvironment(process.env, codexAccessToken);

    const clone = runCommand(
      [config.hostGitBin, "clone", "--depth", "1", "--branch", String(task.default_branch), String(task.clone_url), workspace],
      undefined,
      gitEnv,
      180,
    );
    writeJsonAtomic(join(attemptDir, "clone.json"), redactedCommandResult(clone));
    if (clone.returncode !== 0) {
      return failTask(path, task, "clone_failed", clone.stderr);
    }

    const prNumber = prNumberForTask(task);
    const reviewContextToken = prNumber
      ? await installationToken(config, task.installation_id, reviewContextInstallationTokenRequest(task.repository_id))
      : "";
    const reviewContext = await prepareReviewContext(config, task, workspace, reviewContextToken, gitEnv, attemptDir);
    if (reviewContext) {
      const reviewContextPath = join(attemptDir, "review-context.json");
      writeJsonAtomic(reviewContextPath, reviewContext);
      task.review_context_path = reviewContextPath;
      task.review_context_sha256 = fileSha256(reviewContextPath);
      task.review_evidence = reviewEvidence(reviewContext, reviewContextPath, task);
      writeJsonAtomic(path, task);
    }

    const firstCycle = runCovenCodeCycle(config, task, workspace, reviewContext, attemptDir, runtimeEnv, 0);
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
      const repairCycle = runCovenCodeCycle(config, repairTask, workspace, reviewContext, attemptDir, runtimeEnv, iteration, instruction);
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
    runPublicationValidationChecks(config, task, workspace, attemptDir);
    refreshPublicationWorkspaceEvidence(config, task, workspace, attemptDir);
    task.publication_state = "publication_pending";
    writeJsonAtomic(path, task);
    return resumeTaskPublication(config, taskId);
  } catch (error) {
    return failTask(path, task, "infra_error", String((error as Error).stack || error));
  }
}

export function runnableTaskIds(
  config: AdapterConfig,
  debug: (message: string) => void = (message) => console.log(message),
): string[] {
  const ids: string[] = [];
  for (const entry of readdirSync(config.tasksDir, {withFileTypes: true})) {
    if (!entry.isFile() || !entry.name.endsWith(".json")) continue;
    const id = entry.name.slice(0, -5);
    if (!validRecordId(id)) continue;
    try {
      const task = readStateJson<JsonObject>(join(config.tasksDir, entry.name), {});
      if (task.state === "queued" || task.state === "running" || publicationRecoveryEligible(task) || revisionReconciliationRecoveryEligible(task)) ids.push(id);
    } catch (error) {
      debug(`COVEN GITHUB TASK RECOVERY SKIP task_id=${id} unreadable task: ${redactTokenish(String((error as Error).message || error))}`);
    }
  }
  return ids;
}

export type InstallationTokenProvider = (
  config: AdapterConfig,
  task: JsonObject,
) => Promise<string>;

async function publicationToken(config: AdapterConfig, task: JsonObject): Promise<string> {
  return installationToken(
    config,
    task.installation_id,
    publicationInstallationTokenRequest(task.repository_id),
  );
}

interface RevisionReconciliationResult {
  revision: PullRevision;
  dismissedIds: number[];
}

async function reconcileOnePullRequestRevision(
  config: AdapterConfig,
  task: JsonObject,
  repo: string,
  prNumber: number,
  token: string,
): Promise<RevisionReconciliationResult> {
  const lock = await acquirePublicationLock(config, `${repo}#pr:${prNumber}`);
  try {
    const storedPath = publicationRecordPath(config, repo, prNumber);
    const stored = readStateJson<JsonObject>(storedPath, {});
    const trust = publicationTrust(config, task, `${repo}#pr:${prNumber}`);
    const dismissedIds = new Set<number>();
    let lastRevision: PullRevision = {headSha: "", baseSha: ""};
    for (let pass = 0; pass < 4; pass += 1) {
      const currentRevision = await currentPullRevision(repo, prNumber, token);
      if (!currentRevision.headSha || !currentRevision.baseSha) {
        throw new Error("GitHub did not return the current pull request head and base revisions");
      }
      lastRevision = currentRevision;
      const reviews = await githubRequestAllPages(`https://api.github.com/repos/${repo}/pulls/${prNumber}/reviews`, token);
      const staleReviews = trustedPublications(reviews, trust).filter((review) => {
        const reviewId = Number(review.id || review.review_id || 0);
        return decisiveReviewState(review.state)
          && !dismissedIds.has(reviewId)
          && !publicationFreshForRevision(review, currentRevision, stored);
      });
      for (const review of staleReviews) {
        const dismissed = await dismissReviewForStaleRevision(repo, prNumber, token, review, String(review.body || ""));
        const reviewId = Number(dismissed.review.id || review.id || 0);
        if (reviewId) dismissedIds.add(reviewId);
        if (reviewId && reviewId === Number(stored.review_id || 0)) {
          stored.decision = "DISMISSED";
          stored.review_body = dismissed.body;
          stored.reconciled_at = utcNow();
          writeJsonAtomic(storedPath, stored);
        }
      }
      const verifiedRevision = await currentPullRevision(repo, prNumber, token);
      if (samePullRevision(currentRevision, verifiedRevision)) {
        return {revision: verifiedRevision, dismissedIds: [...dismissedIds]};
      }
      lastRevision = verifiedRevision;
    }
    throw new Error(`Pull request revision did not stabilize while reconciling ${repo}#${prNumber} at ${lastRevision.headSha}/${lastRevision.baseSha}`);
  } finally {
    releasePublicationLock(lock);
  }
}

function revisionReconciliationTask(task: JsonObject): boolean {
  const kind = String(((task.task as JsonObject | undefined) || {}).kind || "");
  return ["reconcile_pull_request_revision", "reconcile_base_branch_push"].includes(kind);
}

export function taskSchedulingClass(config: AdapterConfig, taskId: string): "maintenance" | "compute" {
  try {
    return revisionReconciliationTask(readStateJson<JsonObject>(taskPath(config, taskId), {})) ? "maintenance" : "compute";
  } catch {
    return "maintenance";
  }
}

function revisionReconciliationRecoveryEligible(task: JsonObject): boolean {
  return revisionReconciliationTask(task)
    && task.state === "failed"
    && task.publication_state === "revision_reconciliation_retry_pending";
}

function retryDelayMs(task: JsonObject, attempt: number, error?: unknown): number {
  const generic = Math.min(MAX_GENERIC_RETRY_DELAY_MS, 5_000 * (2 ** Math.min(10, Math.max(0, attempt - 1))));
  const jitterByte = Number.parseInt(sha256(`${String(task.task_id || "task")}:${attempt}`).slice(0, 2), 16);
  const jittered = Math.round(generic * (0.75 + (jitterByte / 255) * 0.5));
  return Math.max(jittered, error instanceof GithubApiError ? error.retryAfterMs : 0);
}

function persistRetryDeadline(task: JsonObject, attempt: number, error?: unknown): void {
  task.retry_not_before = new Date(Date.now() + retryDelayMs(task, attempt, error)).toISOString();
}

function retryDeadlineReached(task: JsonObject): boolean {
  const deadline = Date.parse(String(task.retry_not_before || ""));
  return !Number.isFinite(deadline) || deadline <= Date.now();
}

function failRevisionReconciliation(path: string, task: JsonObject, error: unknown): JsonObject {
  task.state = "failed";
  task.failure_category = "revision_reconciliation_failed";
  task.failure_detail = redactTokenish(String((error as Error).stack || error)).slice(-4000);
  task.publication_state = "revision_reconciliation_retry_pending";
  persistRetryDeadline(task, Number(task.attempts || 1), error);
  task.updated_at = utcNow();
  writeJsonAtomic(path, task);
  return task;
}

async function reconcilePullRequestRevisionTask(config: AdapterConfig, path: string, task: JsonObject): Promise<JsonObject> {
  const taskData = (task.task as JsonObject | undefined) || {};
  const kind = String(taskData.kind || "");
  const repo = String(task.repository || "");
  task.state = "running";
  task.attempts = Number(task.attempts || 0) + 1;
  task.updated_at = utcNow();
  writeJsonAtomic(path, task);
  try {
    if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repo)) {
      throw new Error("A valid repository is required for revision reconciliation");
    }
    const publication = (task.publication as JsonObject | undefined) || {};
    if ((publication.mode || "record_only") !== "comment") {
      task.state = "completed";
      task.publication_state = "revision_reconciliation_not_required";
      task.updated_at = utcNow();
      writeJsonAtomic(path, task);
      return task;
    }
    const policyIssue = nativeReviewReadinessIssue(config, (task.policy_snapshot as JsonObject | undefined) || {});
    if (policyIssue) throw new Error(policyIssue);

    const token = await publicationToken(config, task);
    const results: JsonObject[] = [];
    if (kind === "reconcile_base_branch_push") {
      const baseRef = String(taskData.base_ref || "");
      if (!baseRef || baseRef.includes("\n") || baseRef.includes("\r")) throw new Error("A valid base branch ref is required for push reconciliation");
      const pulls = await githubRequestAllPages(`https://api.github.com/repos/${repo}/pulls?state=open&base=${encodeURIComponent(baseRef)}`, token);
      for (const pull of pulls) {
        const prNumber = Number(pull.number || 0);
        if (!Number.isSafeInteger(prNumber) || prNumber <= 0) throw new Error("GitHub returned an invalid open pull request number");
        const result = await reconcileOnePullRequestRevision(config, task, repo, prNumber, token);
        results.push({
          pr_number: prNumber,
          head_sha: result.revision.headSha,
          base_sha: result.revision.baseSha,
          dismissed_review_ids: result.dismissedIds,
        });
      }
      task.reconciled_base_ref = baseRef;
    } else {
      const prNumber = Number(taskData.pr_number || 0);
      if (!Number.isSafeInteger(prNumber) || prNumber <= 0) throw new Error("A valid pull request number is required for revision reconciliation");
      const result = await reconcileOnePullRequestRevision(config, task, repo, prNumber, token);
      results.push({
        pr_number: prNumber,
        head_sha: result.revision.headSha,
        base_sha: result.revision.baseSha,
        dismissed_review_ids: result.dismissedIds,
      });
    }
    const dismissedIds = results.flatMap((result) => Array.isArray(result.dismissed_review_ids) ? result.dismissed_review_ids as JsonValue[] : []);
    task.state = "completed";
    task.publication_state = dismissedIds.length ? "stale_decisive_reviews_dismissed" : "revision_reconciled_no_stale_reviews";
    task.reconciliation_results = results;
    if (results.length === 1) {
      task.reconciled_revision = {head_sha: results[0].head_sha, base_sha: results[0].base_sha};
      task.dismissed_review_ids = results[0].dismissed_review_ids;
    }
    delete task.failure_category;
    delete task.failure_detail;
    task.updated_at = utcNow();
    writeJsonAtomic(path, task);
    return task;
  } catch (error) {
    return failRevisionReconciliation(path, task, error);
  }
}

function publicationRecoveryEligible(task: JsonObject): boolean {
  if (!["completed", "failed"].includes(String(task.state || ""))) return false;
  const state = String(task.publication_state || "");
  return state === "publication_pending" || state === "publication_failed";
}

export async function resumeTaskPublication(
  config: AdapterConfig,
  taskId: string,
  debug: (message: string) => void = (message) => console.log(message),
  tokenProvider: InstallationTokenProvider = publicationToken,
): Promise<JsonObject> {
  const lock = await acquirePublicationLock(config, `task:${taskId}`);
  const path = taskPath(config, taskId);
  try {
    const task = readStateJson<JsonObject>(path, {});
    if (!publicationRecoveryEligible(task)) return task;
    if (task.publication_state === "publication_failed" && !retryDeadlineReached(task)) return task;
    const isolation = (task.runtime_isolation as JsonObject | undefined) || {};
    if (isolation.mode !== "bwrap" || isolation.verified !== true) {
      task.publication_state = "publication_blocked_unverified_runtime";
      task.publication_error = "Publication was blocked because the task lacks a verified runtime-isolation receipt.";
      task.updated_at = utcNow();
      writeJsonAtomic(path, task);
      return task;
    }
    const publication = (task.publication as JsonObject | undefined) || {};
    if ((publication.mode || "record_only") !== "comment") {
      task.publication_state = "held_for_issue_11_publication_gates";
      task.updated_at = utcNow();
      writeJsonAtomic(path, task);
      return task;
    }
    if (prNumberForTask(task)) {
      const policyIssue = nativeReviewReadinessIssue(config, (task.policy_snapshot as JsonObject | undefined) || {});
      if (policyIssue) {
        task.publication_state = "publication_blocked_unsafe_policy";
        task.publication_error = policyIssue;
        task.updated_at = utcNow();
        writeJsonAtomic(path, task);
        return task;
      }
    }
    const resultPath = String(task.result_path || "");
    if (!resultPath || !existsSync(resultPath)) {
      task.publication_state = "publication_blocked_missing_result";
      task.publication_error = "The finalized task has no readable result artifact.";
      task.updated_at = utcNow();
      writeJsonAtomic(path, task);
      return task;
    }
    let result: JsonObject;
    try {
      result = readBoundedRuntimeResult(resultPath);
    } catch (error) {
      task.publication_state = "publication_blocked_invalid_result";
      task.publication_error = `The finalized task result artifact was rejected: ${redactTokenish(String((error as Error).message || error))}`;
      task.updated_at = utcNow();
      writeJsonAtomic(path, task);
      return task;
    }

    task.publication_state = "publication_pending";
    task.publication_attempts = Number(task.publication_attempts || 0) + 1;
    delete task.retry_not_before;
    task.publication_last_attempt_at = utcNow();
    task.updated_at = utcNow();
    writeJsonAtomic(path, task);
    try {
      const token = await tokenProvider(config, task);
      await publishResultIfConfigured(config, task, resultPath, token, result);
    } catch (error) {
      task.publication_state = "publication_failed";
      task.publication_error = redactTokenish(String((error as Error).stack || error));
      persistRetryDeadline(task, Number(task.publication_attempts || 1), error);
      debug(`COVEN GITHUB PUBLICATION RECOVERY FAIL task_id=${taskId} ${task.publication_error}`);
    }
    if (task.publication_state === "publication_failed" && !task.retry_not_before) {
      persistRetryDeadline(task, Number(task.publication_attempts || 1));
    } else if (task.publication_state !== "publication_failed") {
      delete task.retry_not_before;
    }
    task.updated_at = utcNow();
    writeJsonAtomic(path, task);
    return task;
  } finally {
    releasePublicationLock(lock);
  }
}

export async function recoverPendingPublications(
  config: AdapterConfig,
  debug: (message: string) => void = (message) => console.log(message),
  tokenProvider: InstallationTokenProvider = publicationToken,
): Promise<number> {
  let attempted = 0;
  for (const entry of readdirSync(config.tasksDir, {withFileTypes: true})) {
    if (!entry.isFile() || !entry.name.endsWith(".json")) continue;
    const id = entry.name.slice(0, -5);
    let task: JsonObject;
    try {
      task = readStateJson<JsonObject>(join(config.tasksDir, entry.name), {});
    } catch (error) {
      debug(`COVEN GITHUB PUBLICATION RECOVERY SKIP task_id=${id} unreadable task: ${redactTokenish(String((error as Error).message || error))}`);
      continue;
    }
    if (!publicationRecoveryEligible(task)) continue;
    attempted += 1;
    try {
      await resumeTaskPublication(config, id, debug, tokenProvider);
    } catch (error) {
      debug(`COVEN GITHUB PUBLICATION RECOVERY SKIP task_id=${id} ${redactTokenish(String((error as Error).stack || error))}`);
    }
  }
  return attempted;
}

function publicationValidationCommands(task: JsonObject): string[] {
  const publication = (task.publication as JsonObject | undefined) || {};
  return (Array.isArray(publication.validation_commands) ? publication.validation_commands : [])
    .filter((command): command is string => typeof command === "string" && Boolean(command.trim()))
    .map((command) => command.trim())
    .slice(0, 10);
}

function sandboxScratchMounts(attemptDir: string, workspace: string, name: string): SandboxMounts {
  const inputDir = join(attemptDir, `${name}-input`);
  const outputDir = join(attemptDir, `${name}-output`);
  mkdirSync(inputDir, {recursive: true});
  mkdirSync(outputDir, {recursive: true});
  return {workspace, inputDir, outputDir};
}

function validationEnvironment(): NodeJS.ProcessEnv {
  return {
    PATH: "/usr/local/bin:/usr/bin:/bin",
    HOME: "/home/coven",
    TMPDIR: "/tmp",
    GIT_CONFIG_GLOBAL: "/dev/null",
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_TERMINAL_PROMPT: "0",
  };
}

function runPublicationValidationChecks(config: AdapterConfig, task: JsonObject, workspace: string, attemptDir: string): void {
  const evidence = (task.review_evidence as JsonObject | undefined) || {};
  if (!Object.keys(evidence).length) return;
  const publication = (task.publication as JsonObject | undefined) || {};
  const requestedTimeout = Number(publication.validation_timeout_seconds || 300);
  const timeoutSeconds = Number.isFinite(requestedTimeout) ? Math.max(10, Math.min(1800, Math.trunc(requestedTimeout))) : 300;
  const receipts: JsonObject[] = [];
  for (const [index, command] of publicationValidationCommands(task).entries()) {
    const mounts = sandboxScratchMounts(attemptDir, workspace, `publication-check-${index + 1}`);
    const result = runSandboxedCommand(
      config,
      mounts,
      [config.runtimeShellBin, "-lc", command],
      validationEnvironment(),
      timeoutSeconds,
      "none",
    );
    const artifactPath = join(attemptDir, `publication-check-${index + 1}.json`);
    writeJsonAtomic(artifactPath, redactedCommandResult(result));
    receipts.push({
      command,
      returncode: result.returncode,
      stdout_sha256: sha256(result.stdout),
      stderr_sha256: sha256(result.stderr),
      artifact_path: artifactPath,
      completed_at: utcNow(),
    });
  }
  evidence.host_validation_checks = receipts;
  task.review_evidence = evidence;
}

function refreshPublicationWorkspaceEvidence(config: AdapterConfig, task: JsonObject, workspace: string, attemptDir: string): void {
  const evidence = (task.review_evidence as JsonObject | undefined) || {};
  if (!Object.keys(evidence).length) return;
  const mounts = sandboxScratchMounts(attemptDir, workspace, "publication-git-evidence");
  const gitPrefix = [config.runtimeGitBin, "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null"];
  const head = runSandboxedCommand(config, mounts, [...gitPrefix, "rev-parse", "HEAD"], validationEnvironment(), 30, "none");
  const status = runSandboxedCommand(config, mounts, [...gitPrefix, "status", "--porcelain", "--untracked-files=all"], validationEnvironment(), 30, "none");
  evidence.publication_workspace_head_sha = head.returncode === 0 ? head.stdout.trim() : "";
  evidence.publication_workspace_clean = status.returncode === 0 && status.stdout.trim() === "";
  evidence.publication_workspace_evidence = {
    head_returncode: head.returncode,
    status_returncode: status.returncode,
    head_stdout_sha256: sha256(head.stdout),
    status_stdout_sha256: sha256(status.stdout),
  };
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

  const fetch = runCommand([config.hostGitBin, "fetch", "--depth", "1", "origin", `pull/${prNumber}/head`], workspace, env, 180);
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

  const checkout = runCommand([config.hostGitBin, "checkout", "--detach", "FETCH_HEAD"], workspace, env);
  writeJsonAtomic(join(attemptDir, "checkout-pr.json"), redactedCommandResult(checkout));
  const head = runCommand([config.hostGitBin, "rev-parse", "HEAD"], workspace, env);
  const status = runCommand([config.hostGitBin, "status", "--short", "--branch"], workspace, env);
  writeJsonAtomic(join(attemptDir, "workspace-git.json"), redactedCommandResult({
    args: ["git evidence"],
    returncode: head.returncode === 0 && status.returncode === 0 ? 0 : 1,
    stdout: `HEAD=${head.stdout.trim()}\n${status.stdout.trim()}`,
    stderr: head.stderr + status.stderr,
    signal: head.signal || status.signal,
    timed_out: head.timed_out || status.timed_out,
    spawn_error: [head.spawn_error, status.spawn_error].filter(Boolean).join("\n"),
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

interface PublicationLockOwner {
  owner: string;
  pid: number;
  hostname: string;
  boot_id: string;
  process_start: string;
}

function linuxBootId(): string {
  try {
    return readFileSync("/proc/sys/kernel/random/boot_id", "utf8").trim();
  } catch {
    return "";
  }
}

function linuxProcessStart(pid: number): string {
  try {
    const stat = readFileSync(`/proc/${pid}/stat`, "utf8");
    const fields = stat.slice(stat.lastIndexOf(")") + 2).split(" ");
    return fields[19] || "";
  } catch {
    return "";
  }
}

function publicationLockOwner(owner: string): PublicationLockOwner {
  return {
    owner,
    pid: process.pid,
    hostname: hostname(),
    boot_id: linuxBootId(),
    process_start: linuxProcessStart(process.pid),
  };
}

function parsePublicationLockOwner(raw: string): PublicationLockOwner | null {
  try {
    const parsed = JSON.parse(raw) as PublicationLockOwner;
    if (!parsed.owner || !Number.isSafeInteger(parsed.pid) || parsed.pid <= 0 || !parsed.hostname) return null;
    return parsed;
  } catch {
    return null;
  }
}

function publicationLockOwnerAlive(owner: PublicationLockOwner): boolean | null {
  if (owner.hostname !== hostname()) return null;
  const bootId = linuxBootId();
  if (!bootId || !owner.boot_id || !owner.process_start) return null;
  if (owner.boot_id !== bootId) return false;
  const processStart = linuxProcessStart(owner.pid);
  return processStart ? processStart === owner.process_start : false;
}

async function acquirePublicationLock(config: AdapterConfig, key: string): Promise<PublicationLock> {
  const path = join(config.publicationsDir, `${sha256(key).slice(0, 24)}.lock`);
  const owner = randomUUID();
  const ownerRecord = publicationLockOwner(owner);
  const ownerText = `${stableCompactStringify(ownerRecord as unknown as JsonObject)}\n`;
  while (true) {
    const candidatePath = `${path}.candidate-${owner}`;
    try {
      mkdirSync(candidatePath, {mode: 0o700});
      const candidateOwnerPath = join(candidatePath, "owner");
      writeFileSync(candidateOwnerPath, ownerText, {encoding: "utf8", flag: "wx", mode: 0o600});
      try {
        renameSync(candidatePath, path);
      } catch (error) {
        rmSync(candidatePath, {recursive: true, force: true});
        if (!["EEXIST", "ENOTEMPTY"].includes(String((error as NodeJS.ErrnoException).code || ""))) throw error;
        const contention = new Error("Publication lock already exists") as NodeJS.ErrnoException;
        contention.code = "EEXIST";
        throw contention;
      }
      assertTrustedDirectory(path, "publication lock directory");
      const ownerPath = join(path, "owner");
      const heartbeat = setInterval(() => {
        const refreshPath = join(path, `.owner-refresh-${owner}`);
        try {
          const ownerEntry = lstatIfPresent(ownerPath);
          if (!ownerEntry?.isFile() || ownerEntry.isSymbolicLink()) throw new Error("publication lock owner file became untrusted");
          const currentOwner = parsePublicationLockOwner(readFileSync(ownerPath, "utf8"));
          if (currentOwner?.owner === owner) {
            writeFileSync(refreshPath, ownerText, {encoding: "utf8", flag: "wx", mode: 0o600});
            renameSync(refreshPath, ownerPath);
          }
        } catch {
          clearInterval(heartbeat);
        } finally {
          if (lstatIfPresent(refreshPath)) rmSync(refreshPath, {force: true});
        }
      }, 10_000);
      heartbeat.unref();
      return {path, owner, heartbeat};
    } catch (error) {
      if (lstatIfPresent(candidatePath)) rmSync(candidatePath, {recursive: true, force: true});
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
      try {
        assertTrustedDirectory(path, "existing publication lock directory");
        const ownerPath = join(path, "owner");
        const ownerEntry = lstatIfPresent(ownerPath);
        if (ownerEntry && (ownerEntry.isSymbolicLink() || !ownerEntry.isFile())) {
          throw new Error("Existing publication lock owner is not a regular file");
        }
        const leaseMtime = Number(ownerEntry ? ownerEntry.mtimeMs : lstatSync(path).mtimeMs);
        const existingOwner = ownerEntry ? parsePublicationLockOwner(readFileSync(ownerPath, "utf8")) : null;
        if (existingOwner && publicationLockOwnerAlive(existingOwner) === false) {
          const stalePath = `${path}.stale-${owner}`;
          try {
            renameSync(path, stalePath);
          } catch (renameError) {
            if ((renameError as NodeJS.ErrnoException).code === "ENOENT") continue;
            throw renameError;
          }
          rmSync(stalePath, {recursive: true, force: true});
          continue;
        }
        if (!ownerEntry && Date.now() - leaseMtime > 2 * 60 * 1000) {
          const stalePath = `${path}.ownerless-${owner}`;
          try {
            renameSync(path, stalePath);
          } catch (renameError) {
            if ((renameError as NodeJS.ErrnoException).code === "ENOENT") continue;
            throw renameError;
          }
          rmSync(stalePath, {recursive: true, force: true});
          continue;
        }
        if (Date.now() - leaseMtime > 2 * 60 * 1000 && (!existingOwner || publicationLockOwnerAlive(existingOwner) === null)) {
          throw new Error(`Publication lock ${basename(path)} is stale but its owner cannot be proven dead; refusing an unsafe automatic takeover.`);
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
    assertTrustedDirectory(lock.path, "publication lock directory");
    const ownerEntry = lstatIfPresent(join(lock.path, "owner"));
    if (!ownerEntry?.isFile() || ownerEntry.isSymbolicLink()) throw new Error("Publication lock owner is not a regular file");
    if (parsePublicationLockOwner(readFileSync(join(lock.path, "owner"), "utf8"))?.owner !== lock.owner) return;
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
    base_sha: evidence.base_sha,
    result,
  }));
}

function legacyPublicationIdentity(task: JsonObject, result: JsonObject): string {
  const evidence = (task.review_evidence as JsonObject | undefined) || {};
  return sha256(stableCompactStringify({
    task_id: task.task_id,
    head_sha: evidence.head_sha,
    result,
  }));
}

function publicationIdentityCandidates(task: JsonObject, result: JsonObject): string[] {
  return [...new Set([publicationIdentity(task, result), legacyPublicationIdentity(task, result)])];
}

interface PublicationTrust {
  signingSecret: string;
  verificationSecrets: string[];
  target: string;
  botUsernames: Set<string>;
}

function publicationTrust(config: AdapterConfig, task: JsonObject, target: string): PublicationTrust {
  if (!config.publicationSigningSecret) throw new Error("COVEN_PUBLICATION_SIGNING_SECRET or GITHUB_WEBHOOK_SECRET is required to sign publication identities");
  const policy = (task.policy_snapshot as JsonObject | undefined) || {};
  return {
    signingSecret: config.publicationSigningSecret,
    verificationSecrets: config.publicationVerificationSecrets,
    target,
    botUsernames: new Set((Array.isArray(policy.bot_usernames) ? policy.bot_usernames : []).map((name) => String(name).toLowerCase())),
  };
}

function markerCreatedAt(taskCreatedAt?: JsonValue): string {
  return typeof taskCreatedAt === "string" && Number.isFinite(Date.parse(taskCreatedAt)) ? taskCreatedAt : "";
}

function publicationProof(trust: PublicationTrust, identity: string, createdAt: string, baseSha = "", secret = trust.signingSecret): string {
  const material = baseSha
    ? `${trust.target}\0${identity}\0${createdAt}\0${baseSha}`
    : `${trust.target}\0${identity}\0${createdAt}`;
  return createHmac("sha256", secret).update(material).digest("hex");
}

function publicationMarker(trust: PublicationTrust, identity: string, taskCreatedAt?: JsonValue, baseShaValue?: JsonValue): string {
  const createdAt = markerCreatedAt(taskCreatedAt);
  const baseSha = typeof baseShaValue === "string" && /^[A-Za-z0-9._-]{1,128}$/.test(baseShaValue) ? baseShaValue : "";
  return [
    `<!-- covencat-publication:${identity} -->`,
    createdAt ? `<!-- covencat-task-created:${createdAt} -->` : "",
    baseSha ? `<!-- covencat-review-base:${baseSha} -->` : "",
    `<!-- covencat-publication-proof:${publicationProof(trust, identity, createdAt, baseSha)} -->`,
  ].filter(Boolean).join("\n");
}

interface ParsedPublicationMarker {
  identity: string;
  createdAt: string;
  baseSha: string;
  proof: string;
  raw: string;
  index: number;
}

function publicationMarkerFromBody(item: JsonObject): ParsedPublicationMarker {
  const body = String(item.body || "");
  let marker: ParsedPublicationMarker = {identity: "", createdAt: "", baseSha: "", proof: "", raw: "", index: -1};
  const pattern = /<!-- covencat-publication:([a-f0-9]{64}) -->\r?\n(?:(?:<!-- covencat-task-created:([^>\r\n]+) -->)\r?\n)?(?:(?:<!-- covencat-review-base:([A-Za-z0-9._-]{1,128}) -->)\r?\n)?<!-- covencat-publication-proof:([a-f0-9]{64}) -->/g;
  for (const match of body.matchAll(pattern)) {
    marker = {identity: match[1] || "", createdAt: match[2] || "", baseSha: match[3] || "", proof: match[4] || "", raw: match[0], index: match.index ?? -1};
  }
  return marker;
}

function publicationIdentityFromBody(item: JsonObject): string {
  return publicationMarkerFromBody(item).identity;
}

function publicationCreatedAtFromBody(item: JsonObject): string {
  return publicationMarkerFromBody(item).createdAt;
}

function publicationBaseFromBody(item: JsonObject): string {
  return publicationMarkerFromBody(item).baseSha;
}

function trustedPublication(item: JsonObject, trust: PublicationTrust): boolean {
  const {identity, createdAt, baseSha, proof} = publicationMarkerFromBody(item);
  const user = (item.user as JsonObject | undefined) || {};
  const login = String(user.login || "").toLowerCase();
  if (!identity || !proof || user.type !== "Bot" || (trust.botUsernames.size && !trust.botUsernames.has(login))) return false;
  const actual = Buffer.from(proof, "hex");
  return trust.verificationSecrets.some((secret) => {
    const expected = Buffer.from(publicationProof(trust, identity, createdAt, baseSha, secret), "hex");
    return actual.length === expected.length && timingSafeEqual(actual, expected);
  });
}

function publicationSignedWithCurrentKey(item: JsonObject, trust: PublicationTrust): boolean {
  const {identity, createdAt, baseSha, proof} = publicationMarkerFromBody(item);
  if (!identity || !proof) return false;
  const actual = Buffer.from(proof, "hex");
  const expected = Buffer.from(publicationProof(trust, identity, createdAt, baseSha), "hex");
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}

function resignPublicationBody(item: JsonObject, trust: PublicationTrust): string {
  const body = String(item.body || "");
  const marker = publicationMarkerFromBody(item);
  if (!marker.identity || marker.index < 0 || !marker.raw) throw new Error("Cannot re-sign a publication without a complete marker");
  const replacement = publicationMarker(trust, marker.identity, marker.createdAt, marker.baseSha);
  return `${body.slice(0, marker.index)}${replacement}${body.slice(marker.index + marker.raw.length)}`;
}

async function resignReviewMarkers(repo: string, prNumber: number, token: string, reviews: JsonObject[], trust: PublicationTrust): Promise<void> {
  for (const review of reviews) {
    if (publicationSignedWithCurrentKey(review, trust)) continue;
    const reviewId = Number(review.id || 0);
    if (!reviewId) throw new Error("Cannot re-sign a GitHub review without an ID");
    const body = resignPublicationBody(review, trust);
    await githubRequest("PUT", `https://api.github.com/repos/${repo}/pulls/${prNumber}/reviews/${reviewId}`, token, {body});
    review.body = body;
  }
}

function trustedPublications(items: JsonObject[], trust: PublicationTrust): JsonObject[] {
  return items.filter((item) => trustedPublication(item, trust));
}

function publicationWithIdentity(items: JsonObject[], identities: string | string[], trust: PublicationTrust): JsonObject | undefined {
  const candidates = new Set(Array.isArray(identities) ? identities : [identities]);
  return latestCovencatPublication(trustedPublications(items, trust).filter((item) => candidates.has(publicationIdentityFromBody(item))));
}

function latestCovencatPublication(items: JsonObject[]): JsonObject | undefined {
  return items.reduce<JsonObject | undefined>((latest, item) => !latest || publicationGeneration(item) >= publicationGeneration(latest) ? item : latest, undefined);
}

function publicationGeneration(item: JsonObject): number {
  const bodyCreatedAt = publicationCreatedAtFromBody(item);
  const created = Date.parse(bodyCreatedAt || String(item.submitted_at || item.published_at || ""));
  return Number.isFinite(created) ? created : Number(item.id || 0);
}

function publicationMatchesRevision(review: JsonObject, revision: PullRevision, stored: JsonObject): boolean {
  if (String(review.commit_id || "") !== revision.headSha) return false;
  const markerBase = publicationBaseFromBody(review);
  if (markerBase) return markerBase === revision.baseSha;
  const reviewId = Number(review.id || review.review_id || 0);
  if (reviewId === Number(stored.review_id || 0) && stored.base_sha) {
    return String(stored.head_sha || "") === revision.headSha && String(stored.base_sha || "") === revision.baseSha;
  }
  // Legacy signed markers did not record the base SHA. Preserve their
  // head-level ordering conservatively until a newer base-aware publication
  // replaces them; this prevents an older task from bypassing a deployed
  // newer review after an upgrade or local state loss.
  return true;
}

function publicationFreshForRevision(review: JsonObject, revision: PullRevision, stored: JsonObject): boolean {
  if (String(review.commit_id || "") !== revision.headSha) return false;
  const markerBase = publicationBaseFromBody(review);
  if (markerBase) return markerBase === revision.baseSha;
  const reviewId = Number(review.id || review.review_id || 0);
  return Boolean(reviewId
    && reviewId === Number(stored.review_id || 0)
    && stored.base_sha
    && String(stored.head_sha || "") === revision.headSha
    && String(stored.base_sha || "") === revision.baseSha);
}

function previousCovencatPublication(items: JsonObject[], identities: string | string[], trust: PublicationTrust): JsonObject | undefined {
  const candidates = new Set(Array.isArray(identities) ? identities : [identities]);
  return latestCovencatPublication(trustedPublications(items, trust).filter((item) => {
    const itemIdentity = publicationIdentityFromBody(item);
    return itemIdentity && !candidates.has(itemIdentity);
  }));
}

function clearPublicationError(task: JsonObject): void {
  delete task.publication_error;
}

function finishReviewPublication(
  task: JsonObject,
  submitted: SubmittedReview,
  pendingDismissals: JsonObject[],
  normalState: string,
): void {
  if (pendingDismissals.length) {
    task.publication_state = "publication_failed";
    task.publication_error = `The review was published, but ${pendingDismissals.length} prior decisive review dismissal${pendingDismissals.length === 1 ? "" : "s"} remain pending.`;
    return;
  }
  task.publication_state = submitted.staleAfterSubmit
    ? "published_review_dismissed_stale"
    : submitted.staleEvidence
      ? "published_review_stale_comment"
      : normalState;
  clearPublicationError(task);
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

function safeReviewNotice(body: string, notice: string, maxLength = 60_000): string {
  const safeBody = redactTokenish(body);
  const safeNotice = redactTokenish(notice).trim();
  const marker = publicationMarkerFromBody({body: safeBody});
  const withoutMarker = marker.index >= 0
    ? `${safeBody.slice(0, marker.index)}${safeBody.slice(marker.index + marker.raw.length)}`.trimEnd()
    : safeBody.trimEnd();
  const suffix = marker.raw ? `${safeNotice}\n\n${marker.raw}` : safeNotice;
  const prefixLength = Math.max(0, maxLength - suffix.length - 2);
  const prefix = withoutMarker.slice(0, prefixLength).trimEnd();
  return prefix ? `${prefix}\n\n${suffix}` : suffix.slice(0, maxLength);
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
    base_sha: ((task.review_evidence as JsonObject | undefined) || {}).base_sha,
    published_at: review.submitted_at || utcNow(),
    previous_identity: previous.identity || publicationIdentityFromBody(previous),
    previous_review_id: previous.review_id || previous.id,
    previous_review_url: previous.review_url || previous.html_url,
    previous_decision: previous.decision || previous.state,
    supersession_pending: pendingDismissals.length > 0,
    pending_dismissals: pendingDismissals,
    submission_pending: submissionPending,
    desired_decision: submissionPending ? decision : undefined,
    review_body: review.body,
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
    ...(decisiveReviewState(record.previous_decision) ? [priorReviewFromRecord(record)] : []),
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

async function reviewAfterAmbiguousDismissal(
  repo: string,
  prNumber: number,
  reviewId: number,
  token: string,
): Promise<JsonObject | null> {
  try {
    const live = (await githubRequest("GET", `https://api.github.com/repos/${repo}/pulls/${prNumber}/reviews/${reviewId}`, token)) as JsonObject;
    if (Number(live.id || live.review_id || 0) !== reviewId) throw new Error("GitHub returned a mismatched review during dismissal recovery");
    return live;
  } catch (error) {
    if (!(error instanceof GithubApiError) || error.status !== 404) throw error;
    const reviews = await githubRequestAllPages(`https://api.github.com/repos/${repo}/pulls/${prNumber}/reviews`, token);
    return reviews.find((candidate) => Number(candidate.id || candidate.review_id || 0) === reviewId) || null;
  }
}

async function reconcilePriorDecisiveReviews(
  repo: string,
  prNumber: number,
  token: string,
  previousReviews: JsonObject[],
  current: JsonObject,
  task: JsonObject,
): Promise<JsonObject[]> {
  const dismissalWarning = "_Warning: GitHub did not permit covencat to dismiss the prior decisive review; maintainers should dismiss it manually._";
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
      let alreadyDismissed = false;
      try {
        const live = await reviewAfterAmbiguousDismissal(repo, prNumber, previousReviewId, token);
        alreadyDismissed = live === null || String(live.state || "").toUpperCase() === "DISMISSED";
      } catch {
        alreadyDismissed = false;
      }
      if (alreadyDismissed) continue;
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
    const currentBody = String(current.body || "");
    if (currentReviewId && currentBody.includes(dismissalWarning)) {
      const cleanedBody = currentBody.replace(`\n\n${dismissalWarning}`, "").replace(dismissalWarning, "").trimEnd();
      try {
        await githubRequest("PUT", `https://api.github.com/repos/${repo}/pulls/${prNumber}/reviews/${currentReviewId}`, token, {body: cleanedBody});
        current.body = cleanedBody;
      } catch (error) {
        throw new Error(`Prior-review dismissal succeeded but warning cleanup must be retried: ${redactTokenish(String((error as Error).stack || error))}`);
      }
    }
    return [];
  }
  task.publication_supersession_state = "prior_decisive_review_dismissal_failed";
  task.publication_supersession_error = errors.join("\n");
  if (pending.length) {
    const currentBody = String(current.body || "");
    if (currentReviewId && currentBody && !currentBody.includes(dismissalWarning)) {
      const warnedBody = safeReviewNotice(currentBody, dismissalWarning);
      try {
        await githubRequest("PUT", `https://api.github.com/repos/${repo}/pulls/${prNumber}/reviews/${currentReviewId}`, token, {
          body: warnedBody,
        });
        current.body = warnedBody;
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
  if (submitted.staleEvidence || submitted.staleAfterSubmit || !evidenceComplete || !decisiveReviewState(submitted.decision)) {
    if (priorReviews.length) {
      task.publication_supersession_state = submitted.staleEvidence || submitted.staleAfterSubmit
        ? "prior_decisive_review_retained_for_stale_replacement"
        : !evidenceComplete
          ? "prior_decisive_review_retained_for_incomplete_replacement"
          : "prior_decisive_review_retained_for_comment_replacement";
      delete task.publication_supersession_error;
    } else {
      delete task.publication_supersession_state;
      delete task.publication_supersession_error;
    }
    return [];
  }
  if (!priorReviews.length) {
    delete task.publication_supersession_state;
    delete task.publication_supersession_error;
    return [];
  }
  const evidenceRevision = reviewEvidenceRevision(task);
  const revisionBeforeDismissal = await currentPullRevision(repo, prNumber, token);
  if (!samePullRevision(revisionBeforeDismissal, evidenceRevision)) {
    const stale = await dismissReviewForStaleRevision(repo, prNumber, token, submitted.review, submitted.body);
    Object.assign(submitted, stale);
    task.publication_supersession_state = "prior_decisive_review_retained_for_stale_replacement";
    delete task.publication_supersession_error;
    return [];
  }
  const pending = await reconcilePriorDecisiveReviews(repo, prNumber, token, priorReviews, submitted.review, task);
  const revisionAfterDismissal = await currentPullRevision(repo, prNumber, token);
  if (!samePullRevision(revisionAfterDismissal, evidenceRevision)) {
    const stale = await dismissReviewForStaleRevision(repo, prNumber, token, submitted.review, submitted.body);
    Object.assign(submitted, stale);
    task.publication_supersession_state = "prior_decisive_reviews_reconciled_before_stale_replacement_dismissal";
  }
  return pending;
}

interface SubmittedReview {
  review: JsonObject;
  body: string;
  decision: string;
  staleAfterSubmit: boolean;
  staleEvidence: boolean;
}

interface PullRevision {
  headSha: string;
  baseSha: string;
}

function reviewEvidenceRevision(task: JsonObject): PullRevision {
  const evidence = (task.review_evidence as JsonObject | undefined) || {};
  return {headSha: String(evidence.head_sha || ""), baseSha: String(evidence.base_sha || "")};
}

function samePullRevision(left: PullRevision, right: PullRevision): boolean {
  return Boolean(left.headSha && left.baseSha && left.headSha === right.headSha && left.baseSha === right.baseSha);
}

async function currentPullRevision(repo: string, prNumber: number, token: string): Promise<PullRevision> {
  const pr = (await githubRequest("GET", `https://api.github.com/repos/${repo}/pulls/${prNumber}`, token)) as JsonObject;
  return {
    headSha: String(((pr.head as JsonObject | undefined) || {}).sha || ""),
    baseSha: String(((pr.base as JsonObject | undefined) || {}).sha || ""),
  };
}

async function dismissReviewForStaleRevision(
  repo: string,
  prNumber: number,
  token: string,
  review: JsonObject,
  body: string,
): Promise<SubmittedReview> {
  const reviewId = Number(review.id || review.review_id || 0);
  if (!reviewId) throw new Error("GitHub did not return an ID for the stale decisive review");
  let liveReview = review;
  const alreadyDismissed = String(review.state || review.decision || "").toUpperCase() === "DISMISSED";
  if (!alreadyDismissed) {
    try {
      await githubRequest("PUT", `https://api.github.com/repos/${repo}/pulls/${prNumber}/reviews/${reviewId}/dismissals`, token, {
        message: "Dismissed automatically because the PR head or base changed after covencat captured its review evidence.",
        event: "DISMISS",
      });
    } catch (error) {
      try {
        const verified = await reviewAfterAmbiguousDismissal(repo, prNumber, reviewId, token);
        if (!verified) {
          return {review: {...review, state: "DISMISSED"}, body, decision: "DISMISSED", staleAfterSubmit: true, staleEvidence: true};
        }
        liveReview = verified;
      } catch {
        throw error;
      }
      if (String(liveReview.state || "").toUpperCase() !== "DISMISSED") throw error;
    }
  }
  const staleNotice = "_This decisive review was dismissed automatically because the PR head or base changed after its evidence was captured._";
  const liveBody = String(liveReview.body || body);
  const publishedBody = liveBody.includes(staleNotice) ? liveBody : safeReviewNotice(liveBody, staleNotice);
  if (publishedBody !== liveBody) {
    await githubRequest("PUT", `https://api.github.com/repos/${repo}/pulls/${prNumber}/reviews/${reviewId}`, token, {body: publishedBody});
  }
  return {review: {...review, ...liveReview, state: "DISMISSED", body: publishedBody}, body: publishedBody, decision: "DISMISSED", staleAfterSubmit: true, staleEvidence: true};
}

async function submitPendingReview(
  repo: string,
  prNumber: number,
  token: string,
  pendingReview: JsonObject,
  desiredDecision: "APPROVE" | "REQUEST_CHANGES" | "COMMENT",
  evidenceRevision: PullRevision,
  body: string,
): Promise<SubmittedReview> {
  const reviewId = Number(pendingReview.id || pendingReview.review_id || 0);
  if (!reviewId) throw new Error("GitHub did not return an ID for the pending review");
  let decision: "APPROVE" | "REQUEST_CHANGES" | "COMMENT" = desiredDecision;
  let publishedBody = body;
  let staleEvidence = false;
  const revisionBeforeSubmit = await currentPullRevision(repo, prNumber, token);
  if (!samePullRevision(revisionBeforeSubmit, evidenceRevision)) {
    staleEvidence = true;
    if (decisiveReviewState(decision)) decision = "COMMENT";
    publishedBody = safeReviewNotice(body, "_The PR head or base changed before this review was submitted, so stale evidence was published as COMMENT._");
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
    publishedBody = safeReviewNotice(body, "_GitHub does not allow the App to submit a decisive review on its own pull request, so this was published as COMMENT._");
    response = (await githubRequest("POST", `https://api.github.com/repos/${repo}/pulls/${prNumber}/reviews/${reviewId}/events`, token, {
      event: decision,
      body: publishedBody,
    })) as JsonObject;
  }
  let review: JsonObject = {...pendingReview, ...response, id: response.id || pendingReview.id, body: publishedBody};
  const revisionAfterSubmit = await currentPullRevision(repo, prNumber, token);
  if (!samePullRevision(revisionAfterSubmit, evidenceRevision)) {
    if (decisiveReviewState(decision)) {
      return dismissReviewForStaleRevision(repo, prNumber, token, review, publishedBody);
    }
    staleEvidence = true;
    publishedBody = safeReviewNotice(publishedBody, "_The PR head or base changed during submission; this COMMENT must not supersede prior decisive review state._");
    await githubRequest("PUT", `https://api.github.com/repos/${repo}/pulls/${prNumber}/reviews/${reviewId}`, token, {body: publishedBody});
    review = {...review, body: publishedBody};
  }
  return {review, body: publishedBody, decision, staleAfterSubmit: false, staleEvidence};
}

async function reconcileSubmittedReviewRevision(
  repo: string,
  prNumber: number,
  token: string,
  submitted: SubmittedReview,
  evidenceRevision: PullRevision,
): Promise<SubmittedReview> {
  const currentRevision = await currentPullRevision(repo, prNumber, token);
  if (samePullRevision(currentRevision, evidenceRevision)) return submitted;
  if (decisiveReviewState(submitted.decision) || String(submitted.review.state || "").toUpperCase() === "DISMISSED" || submitted.decision === "DISMISSED") {
    return dismissReviewForStaleRevision(repo, prNumber, token, submitted.review, submitted.body);
  }
  return {...submitted, staleEvidence: true};
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
  try {
    const normalizedRoot = realpathSync(root);
    const candidate = resolve(normalizedRoot, path);
    if (!candidate.startsWith(`${normalizedRoot}${sep}`) || !existsSync(candidate)) return false;
    let current = normalizedRoot;
    for (const part of path.split("/")) {
      current = join(current, part);
      const details = lstatSync(current);
      if (details.isSymbolicLink()) return false;
    }
    return statSync(candidate).isFile();
  } catch {
    return false;
  }
}

function actionableFinding(finding: JsonObject): boolean {
  return !["info", "informational", "nit", "note"].includes(String(finding.severity || "").toLowerCase()) && Boolean(finding.title || finding.body || finding.recommendation);
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function reportsMissingTestExecution(text: string, command = ""): boolean {
  const normalized = text.toLowerCase()
    .replace(/\b(?:no|zero|0)\s+(?:tests?|testing|checks?|commands?|test\s+suites?|suites?)\s+(?:were\s+)?skipped\b/g, "")
    .replace(/\bnone\s+(?:(?:of\s+)?(?:the\s+)?(?:tests?|testing|checks?|commands?|test\s+suites?|suites?)\s+)?(?:were\s+)?skipped\b/g, "")
    .replace(/\b(?:tests?|testing|checks?|commands?|test\s+suites?|suites?)\s+(?:were\s+)?not\s+skipped\b/g, "");
  if (!normalized.trim()) return false;
  const subject = "(?:tests?|testing|checks?|commands?|test\\s+suites?|suites?)";
  if (new RegExp(`\\b(?:no|zero|0)\\s+${subject}\\b.{0,30}\\b(?:run|executed)\\b`, "i").test(normalized)) return true;
  if (new RegExp(`\\b${subject}\\b.{0,60}\\b(?:not|never)\\s+(?:(?:be|been|actually)\\s+)?(?:run|executed)\\b`, "i").test(normalized)) return true;
  if (new RegExp(`\\b${subject}\\b.{0,60}\\bskip(?:ped)?\\b`, "i").test(normalized)) return true;
  if (new RegExp(`\\b${subject}\\b.{0,60}\\b(?:unable|cannot|can't)\\b.{0,30}\\b(?:run|execute)\\b`, "i").test(normalized)) return true;
  if (/\bnot[ _-]?run\b/.test(normalized)) return true;
  return Boolean(command) && new RegExp(`${escapeRegExp(command.toLowerCase())}.{0,60}(?:not|never|skip(?:ped)?|unable|cannot|can't).{0,30}(?:run|executed)?`, "i").test(normalized);
}

function reportsFailedTestExecution(text: string, command = ""): boolean {
  const normalized = text.toLowerCase()
    .replace(/\b(?:no|zero|0)\s+(?:(?:tests?|checks?|commands?|suites?)\s+)?(?:failed|failing|failures?|errored|errors?)\b/g, "")
    .replace(/\bnone\s+(?:(?:of\s+)?(?:the\s+)?(?:tests?|checks?|commands?|suites?)\s+)?(?:failed|failing|errored)\b/g, "")
    .replace(/\b(?:tests?|checks?|commands?|suites?)\s+(?:failed|failing|errored)\s*:\s*0\b/g, "")
    .replace(/\b(?:failed|failures?|errors?)\s*:\s*0\b/g, "")
    .replace(/\bno\s+(?:failures?|errors?)\b/g, "");
  if (!normalized.trim()) return false;
  if (/\b[1-9]\d*\s+(?:(?:tests?|checks?|commands?|suites?)\s+)?(?:failed|failing|failures?|errors?)\b/.test(normalized)) return true;
  if (/\b[1-9]\d*\s+(?:tests?|checks?|commands?|suites?)\b.{0,30}\bdid\s+not\s+pass\b/.test(normalized)) return true;
  if (/\b(?:failures?|errors?)\s*[:=]\s*[1-9]\d*\b/.test(normalized)) return true;
  if (/(?:^|\n)\s*(?:fail(?:ed)?|error)\b/m.test(normalized)) return true;
  if (/\b(?:tests?|checks?|commands?|suites?)\b.{0,50}\b(?:failed|failing|errored)\b/.test(normalized)) return true;
  if (/\b(?:exit(?:ed)?(?:\s+(?:code|status))?|return(?:ed)?(?:\s+(?:code|status))?)\s*[:=]?\s*[1-9]\d*\b/.test(normalized)) return true;
  if (/\b(?:exit(?:ed)?|return(?:ed)?)\b.{0,20}\b(?:unsuccessfully|non[- ]zero)\b/.test(normalized)) return true;
  return Boolean(command) && new RegExp(`${escapeRegExp(command.toLowerCase())}.{0,50}(?:fail(?:ed|ing)?|errored|unsuccessfully|non[- ]zero|errors?\\s*[:=]\\s*[1-9]\\d*)`, "i").test(normalized);
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

export function normalizeReviewPublication(
  task: JsonObject,
  result: JsonObject,
  currentHeadSha?: string,
  repositoryRoot?: string,
  currentBaseSha?: string,
): NormalizedReviewPublication {
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
  if (!String(evidence.base_sha || "").trim()) validationIssues.push("PR base revision is missing");
  if (!String(evidence.workspace_head_sha || "").trim()) validationIssues.push("checked-out revision is missing");
  if (evidence.workspace_head_sha !== evidence.head_sha) validationIssues.push("checked-out revision does not match the captured PR head");
  if (!String(evidence.publication_workspace_head_sha || "").trim()) validationIssues.push("post-run workspace revision is missing");
  if (evidence.publication_workspace_head_sha !== evidence.head_sha) validationIssues.push("post-run workspace revision does not match the captured PR head");
  if (evidence.publication_workspace_clean !== true) validationIssues.push("post-run workspace contains uncommitted changes");
  if (currentHeadSha !== undefined && !currentHeadSha) validationIssues.push("current PR head could not be verified");
  if (currentHeadSha && currentHeadSha !== evidence.head_sha) validationIssues.push("PR head changed after review evidence was captured");
  if (currentBaseSha !== undefined && !currentBaseSha) validationIssues.push("current PR base could not be verified");
  if (currentBaseSha && currentBaseSha !== evidence.base_sha) validationIssues.push("PR base changed after review evidence was captured");
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

  const hostChecks = (Array.isArray(evidence.host_validation_checks) ? evidence.host_validation_checks : [])
    .filter((item): item is JsonObject => Boolean(item) && typeof item === "object" && !Array.isArray(item));
  if (!Array.isArray(evidence.host_validation_checks) || !hostChecks.length) {
    validationIssues.push("no host-captured validation checks were recorded");
  }
  const successfulHostCommands = new Set<string>();
  for (const check of hostChecks) {
    const command = typeof check.command === "string" ? check.command.trim() : "";
    const returncode = check.returncode;
    const validReceipt = Boolean(command)
      && typeof returncode === "number"
      && Number.isInteger(returncode)
      && /^[a-f0-9]{64}$/.test(String(check.stdout_sha256 || ""))
      && /^[a-f0-9]{64}$/.test(String(check.stderr_sha256 || ""));
    if (!validReceipt) {
      validationIssues.push("host validation check receipt is malformed");
      continue;
    }
    if (returncode !== 0) {
      validationIssues.push(`host validation check ${command} exited ${returncode}`);
      continue;
    }
    successfulHostCommands.add(command);
  }

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
    const invalidPass = status === "passed" && (
      !validShape
      || !command
      || !output
      || reportsMissingTestExecution(output, command)
      || reportsMissingTestExecution(narrative, command)
      || reportsFailedTestExecution(output, command)
      || reportsFailedTestExecution(narrative, command)
      || !successfulHostCommands.has(command)
    );
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
  const revisionMatchesEvidence = !(currentHeadSha !== undefined && currentHeadSha !== evidence.head_sha)
    && !(currentBaseSha !== undefined && currentBaseSha !== evidence.base_sha);
  for (const finding of scopedFindings) {
    const path = repositoryPath(finding.file);
    const line = Number(finding.line);
    const locations = path ? changedLines.get(path) : undefined;
    const side = locations?.RIGHT.has(line) ? "RIGHT" : locations?.LEFT.has(line) ? "LEFT" : null;
    if (revisionMatchesEvidence && path && side && changedFiles.has(path) && Number.isInteger(line) && line > 0 && actionableFinding(finding)) {
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

export async function publishResultIfConfigured(
  config: AdapterConfig,
  task: JsonObject,
  resultPath: string,
  token: string,
  validatedResult?: JsonObject,
): Promise<void> {
  const publication = (task.publication as JsonObject | undefined) || {};
  const mode = publication.mode || "record_only";
  if (mode !== "comment") {
    task.publication_state = "held_for_issue_11_publication_gates";
    return;
  }

  const result = validatedResult || readBoundedRuntimeResult(resultPath);
  const taskData = (task.task as JsonObject | undefined) || {};
  const prNumber = prNumberForTask(task);
  const number = taskData.issue_number || taskData.pr_number || prNumber;
  if (!number) {
    task.publication_state = "publication_skipped_no_issue_or_pr_number";
    return;
  }

  const repo = String(task.repository);
  const identities = publicationIdentityCandidates(task, result);
  const identity = identities[0];
  const publicationLock = await acquirePublicationLock(config, `${repo}#${prNumber ? `pr:${prNumber}` : `issue:${number}`}`);
  try {
    try {
      const hasReview = Object.keys((result.review as JsonObject | undefined) || {}).length > 0;
      const operationalFailure = ["failure", "needs_input"].includes(String(result.status || "")) && !hasReview;
      if (prNumber && !operationalFailure) {
        const recordPath = publicationRecordPath(config, repo, prNumber);
        const stored = readStateJson<JsonObject>(recordPath, {});

        const target = `${repo}#pr:${prNumber}`;
        const trust = publicationTrust(config, task, target);
        const currentRevision = await currentPullRevision(repo, prNumber, token);
        const evidenceRevision = reviewEvidenceRevision(task);
        const reviews = await githubRequestAllPages(`https://api.github.com/repos/${repo}/pulls/${prNumber}/reviews`, token);
        const trustedReviews = trustedPublications(reviews, trust);
        await resignReviewMarkers(repo, prNumber, token, trustedReviews, trust);
        const evidence = (task.review_evidence as JsonObject | undefined) || {};
        const currentRevisionRemote = latestCovencatPublication(trustedReviews.filter((review) => publicationMatchesRevision(review, currentRevision, stored)));
        const evidenceRevisionRemote = latestCovencatPublication(trustedReviews.filter((review) => publicationMatchesRevision(review, evidenceRevision, stored))) || {};
        const evidenceRevisionRemoteIdentity = publicationIdentityFromBody(evidenceRevisionRemote);
        const taskGeneration = Date.parse(String(task.created_at || ""));
        const staleRevision = !samePullRevision(evidenceRevision, currentRevision)
          && (Boolean(currentRevisionRemote)
            || (String(stored.head_sha || "") === currentRevision.headSha && String(stored.base_sha || "") === currentRevision.baseSha));
        const staleGeneration = evidenceRevisionRemoteIdentity
          && !identities.includes(evidenceRevisionRemoteIdentity)
          && Number.isFinite(taskGeneration)
          && publicationGeneration(evidenceRevisionRemote) > taskGeneration;
        const existing = publicationWithIdentity(
          reviews.filter((review) => publicationMatchesRevision(review, evidenceRevision, stored)),
          identities,
          trust,
        );
        if (staleRevision || staleGeneration) {
          const existingState = String(existing?.state || "").toUpperCase();
          if (existing && existingState === "PENDING") {
            await githubRequest("DELETE", `https://api.github.com/repos/${repo}/pulls/${prNumber}/reviews/${Number(existing.id)}`, token);
          } else if (existing && staleRevision && (decisiveReviewState(existing.state) || existingState === "DISMISSED")) {
            const stale = await dismissReviewForStaleRevision(repo, prNumber, token, existing, String(existing.body || ""));
            task.publication_review_id = stale.review.id || existing.id;
            task.publication_url = stale.review.html_url || existing.html_url;
            task.publication_decision = "DISMISSED";
          }
          task.publication_state = staleRevision ? "publication_skipped_stale_revision" : "publication_skipped_stale_run";
          task.publication_identity = identity;
          clearPublicationError(task);
          return;
        }

        if (existing && evidenceRevisionRemoteIdentity && !identities.includes(evidenceRevisionRemoteIdentity) && publicationGeneration(evidenceRevisionRemote) >= publicationGeneration(existing)) {
          if (String(existing.state || "").toUpperCase() === "PENDING") {
            await githubRequest("DELETE", `https://api.github.com/repos/${repo}/pulls/${prNumber}/reviews/${Number(existing.id)}`, token);
          }
          task.publication_state = "publication_skipped_stale_run";
          task.publication_identity = identity;
          clearPublicationError(task);
          return;
        }
        const previous = previousCovencatPublication(reviews, identities, trust)
          || (!identities.includes(String(stored.identity || "")) ? stored : priorReviewFromRecord(stored));
        const repositoryRoot = String(task.workspace_path || join(config.workspacesDir, String(task.task_id), "repo"));
        const normalized = normalizeReviewPublication(task, result, currentRevision.headSha, repositoryRoot, currentRevision.baseSha);
        const priorDecisive = priorDecisiveReviews(reviews, identity, trust, stored);
        if (existing) {
          const recoveredPending = String(existing.state || "").toUpperCase() === "PENDING";
          let submitted = recoveredPending
            ? await submitPendingReview(repo, prNumber, token, existing, normalized.decision, evidenceRevision, String(existing.body || ""))
            : {review: existing, body: String(existing.body || ""), decision: String(existing.state || normalized.decision), staleAfterSubmit: false, staleEvidence: false};
          if (!recoveredPending) submitted = await reconcileSubmittedReviewRevision(repo, prNumber, token, submitted, evidenceRevision);
          const pendingDismissals = await reconcileReplacementSupersession(repo, prNumber, token, priorDecisive, submitted, normalized.evidenceComplete, task);
          const record = publicationRecord(task, identity, submitted.review, submitted.decision, previous, pendingDismissals);
          writeJsonAtomic(recordPath, record);
          finishReviewPublication(task, submitted, pendingDismissals, recoveredPending ? "published_review_recovered" : "publication_skipped_duplicate");
          task.publication_identity = identity;
          task.publication_review_id = submitted.review.id;
          task.publication_url = submitted.review.html_url;
          task.publication_decision = submitted.decision;
          return;
        }

        const storedRevisionCompatible = (!stored.head_sha || String(stored.head_sha) === evidenceRevision.headSha)
          && (!stored.base_sha || String(stored.base_sha) === evidenceRevision.baseSha);
        if (identities.includes(String(stored.identity || "")) && stored.review_id && storedRevisionCompatible) {
          let current: JsonObject = {
            id: stored.review_id,
            review_id: stored.review_id,
            html_url: stored.review_url,
            review_url: stored.review_url,
            body: stored.review_body,
            state: stored.decision,
          };
          let liveState = "";
          try {
            const live = await githubRequest("GET", `https://api.github.com/repos/${repo}/pulls/${prNumber}/reviews/${Number(stored.review_id)}`, token);
            if (!live || typeof live !== "object" || Array.isArray(live)) {
              throw new Error("GitHub returned a malformed response for the locally recorded review; refusing an ambiguous resubmission");
            }
            if (Number(live.id || 0) !== Number(stored.review_id)
              || !identities.includes(publicationIdentityFromBody(live))
              || !trustedPublication(live, trust)) {
              throw new Error("The locally recorded GitHub review did not match its signed App publication; refusing an ambiguous resubmission");
            }
            current = {...current, ...live, body: live.body || current.body};
            liveState = String(live.state || "").toUpperCase();
          } catch (error) {
            if (!(error instanceof GithubApiError) || error.status !== 404) throw error;
            throw new Error("The locally recorded GitHub review no longer exists; refusing an ambiguous resubmission");
          }
          if (!String(current.body || "")) {
            throw new Error("Cannot safely recover a GitHub review without its signed body");
          }
          const recoveredPending = liveState ? liveState === "PENDING" : stored.submission_pending === true;
          let submitted = recoveredPending
            ? await submitPendingReview(repo, prNumber, token, current, normalized.decision, evidenceRevision, String(current.body || ""))
            : {review: current, body: String(current.body || ""), decision: String(current.state || stored.decision || normalized.decision), staleAfterSubmit: false, staleEvidence: false};
          if (!recoveredPending) submitted = await reconcileSubmittedReviewRevision(repo, prNumber, token, submitted, evidenceRevision);
          const pendingDismissals = await reconcileReplacementSupersession(repo, prNumber, token, priorDecisive, submitted, normalized.evidenceComplete, task);
          writeJsonAtomic(recordPath, publicationRecord(task, identity, submitted.review, submitted.decision, previous, pendingDismissals));
          finishReviewPublication(task, submitted, pendingDismissals, "publication_skipped_duplicate");
          task.publication_identity = identity;
          task.publication_review_id = submitted.review.id;
          task.publication_url = submitted.review.html_url;
          task.publication_decision = submitted.decision;
          return;
        }

        for (const pending of trustedReviews.filter((review) => String(review.state || "").toUpperCase() === "PENDING")) {
          await githubRequest("DELETE", `https://api.github.com/repos/${repo}/pulls/${prNumber}/reviews/${Number(pending.id)}`, token);
        }
        let publishedBody = `${safePublicationText(publicationReviewBody(task, result, normalized, previous, identity), 59_700)}\n\n${publicationMarker(trust, identity, task.created_at, evidence.base_sha)}`;
        const reviewPayload: JsonObject = {body: publishedBody, commit_id: evidence.head_sha};
        if (normalized.inlineComments.length) reviewPayload.comments = normalized.inlineComments;
        let pendingReview: JsonObject;
        try {
          pendingReview = (await githubRequest("POST", `https://api.github.com/repos/${repo}/pulls/${prNumber}/reviews`, token, reviewPayload)) as JsonObject;
        } catch (error) {
          if (!normalized.inlineComments.length || !inlineLocationError(error)) throw error;
          publishedBody = safeReviewNotice(publishedBody, "_Inline publication was unavailable; findings are included above._");
          pendingReview = (await githubRequest("POST", `https://api.github.com/repos/${repo}/pulls/${prNumber}/reviews`, token, {
            body: publishedBody,
            commit_id: evidence.head_sha,
          })) as JsonObject;
        }
        pendingReview = {...pendingReview, body: publishedBody, state: pendingReview.state || "PENDING"};
        writeJsonAtomic(recordPath, publicationRecord(task, identity, pendingReview, normalized.decision, previous, priorDecisive, true));
        const submitted = await submitPendingReview(repo, prNumber, token, pendingReview, normalized.decision, evidenceRevision, publishedBody);
        const pendingDismissals = await reconcileReplacementSupersession(repo, prNumber, token, priorDecisive, submitted, normalized.evidenceComplete, task);
        finishReviewPublication(task, submitted, pendingDismissals, "published_review");
        task.publication_identity = identity;
        task.publication_review_id = submitted.review.id;
        task.publication_url = submitted.review.html_url;
        task.publication_decision = submitted.decision;
        writeJsonAtomic(recordPath, publicationRecord(task, identity, submitted.review, submitted.decision, previous, pendingDismissals));
        return;
      }

      const issueTrust = publicationTrust(config, task, `${repo}#issue:${Number(number)}`);
      const body = `${safePublicationText(publicationCommentBody(task, result, "Coven task result"), 59_700)}\n\n${publicationMarker(issueTrust, identity, task.created_at)}`;
      if (identities.includes(String(task.publication_identity || "")) && task.publication_comment_id) {
        try {
          const candidateResponse = await githubRequest("GET", `https://api.github.com/repos/${repo}/issues/comments/${Number(task.publication_comment_id)}`, token);
          if (!candidateResponse || typeof candidateResponse !== "object" || Array.isArray(candidateResponse)) {
            throw new Error("GitHub returned a malformed response for the locally recorded issue comment; refusing an ambiguous republication");
          }
          const candidate = candidateResponse as JsonObject;
          if (Number(candidate.id || 0) !== Number(task.publication_comment_id)) {
            throw new Error("GitHub returned a mismatched issue comment for the locally recorded publication");
          }
          if (identities.includes(publicationIdentityFromBody(candidate)) && trustedPublication(candidate, issueTrust)) {
            if (!publicationSignedWithCurrentKey(candidate, issueTrust)) {
              const resignedBody = resignPublicationBody(candidate, issueTrust);
              await githubRequest("PATCH", `https://api.github.com/repos/${repo}/issues/comments/${Number(candidate.id || task.publication_comment_id)}`, token, {body: resignedBody});
              candidate.body = resignedBody;
            }
            task.publication_state = "publication_skipped_duplicate";
            task.publication_url = candidate.html_url || task.publication_url;
            task.publication_comment_id = candidate.id || task.publication_comment_id;
            clearPublicationError(task);
            return;
          }
        } catch (error) {
          if (!(error instanceof GithubApiError) || error.status !== 404) throw error;
        }
      }
      const comments = await githubRequestAllPages(`https://api.github.com/repos/${repo}/issues/${Number(number)}/comments`, token);
      const existing = publicationWithIdentity(comments, identities, issueTrust);
      if (existing) {
        if (!publicationSignedWithCurrentKey(existing, issueTrust)) {
          const resignedBody = resignPublicationBody(existing, issueTrust);
          await githubRequest("PATCH", `https://api.github.com/repos/${repo}/issues/comments/${Number(existing.id)}`, token, {body: resignedBody});
          existing.body = resignedBody;
        }
        task.publication_state = "publication_skipped_duplicate";
        task.publication_identity = identity;
        task.publication_url = existing.html_url;
        task.publication_comment_id = existing.id;
        clearPublicationError(task);
        return;
      }
      const response = (await githubRequest("POST", `https://api.github.com/repos/${repo}/issues/${Number(number)}/comments`, token, {body})) as JsonObject;
      task.publication_state = "published_comment";
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
  if (previousUrl && previous.identity !== identity) {
    additions.push(`This review follows [the prior covencat publication](${String(previousUrl)}). A decisive submission replaces its state; a COMMENT does not.`);
  }
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

export function runtimeProcessEnvironment(source: NodeJS.ProcessEnv, codexAccessToken: string): NodeJS.ProcessEnv {
  return {
    ...sanitizedRuntimeEnvironment(source),
    PATH: "/usr/local/bin:/usr/bin:/bin",
    HOME: "/home/coven",
    TMPDIR: "/tmp",
    GIT_TERMINAL_PROMPT: "0",
    COVEN_CODE_PROVIDER: "codex",
    COVEN_CODE_HOSTED_REVIEW: "1",
    OPENAI_API_KEY: codexAccessToken,
  };
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

function blockTask(path: string, task: JsonObject, reason: string, detail: string): JsonObject {
  task.state = "blocked";
  task.failure_category = reason;
  task.failure_detail = redactTokenish(String(detail)).slice(-4000);
  task.publication_state = "not_started";
  task.updated_at = utcNow();
  writeJsonAtomic(path, task);
  return task;
}
