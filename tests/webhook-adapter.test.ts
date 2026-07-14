import assert from "node:assert/strict";
import { createHash, createHmac, generateKeyPairSync } from "node:crypto";
import { once } from "node:events";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import type { AddressInfo } from "node:net";
import { hostname, tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { pathToFileURL } from "node:url";

import {
  buildTaskFromEvent,
  createConfig,
  githubRequestAllPages,
  handleRequest,
  normalizeReviewPublication,
  patchEvidenceIncomplete,
  publicationInstallationTokenRequest,
  publishResultIfConfigured,
  readBoundedRuntimeResult,
  recoverPendingPublications,
  redactTokenish,
  reviewContextInstallationTokenRequest,
  resumeTaskPublication,
  runtimeInstallationTokenRequest,
  runtimeIsolationIssue,
  runtimeProcessEnvironment,
  runtimeSandboxArgs,
  runnableTaskIds,
  runTask,
  sanitizedRuntimeEnvironment,
  type JsonObject,
  type JsonValue,
} from "../src/adapter.js";
import { createWebhookServer, createWorkerTaskScheduler } from "../src/server.js";

type GithubMockResult = JsonObject | JsonObject[] | {
  httpStatus: number;
  response: JsonObject | JsonObject[];
  headers?: Record<string, string>;
};

async function withGithubApiMock<T>(handler: (url: string, init: RequestInit) => GithubMockResult | Promise<GithubMockResult>, work: () => Promise<T>): Promise<T> {
  const original = globalThis.fetch;
  globalThis.fetch = async (input, init) => {
    const result = await handler(String(input), init || {});
    if (!Array.isArray(result) && "httpStatus" in result) {
      return new Response(JSON.stringify(result.response), {
        status: Number(result.httpStatus),
        headers: (result as {headers?: Record<string, string>}).headers,
      });
    }
    return new Response(JSON.stringify(result), {status: 200});
  };
  try {
    return await work();
  } finally {
    globalThis.fetch = original;
  }
}

function reviewTask(taskId = "review-task"): JsonObject {
  return {
    task_id: taskId,
    repository: "OpenCoven/example",
    publication: {mode: "comment"},
    runtime_isolation: {mode: "bwrap", verified: true},
    policy_snapshot: {
      bot_usernames: ["covencat[bot]"],
      enabled_triggers: ["pull_request.synchronize", "pull_request.edited", "pull_request.reopened", "push"],
      publication: {mode: "comment"},
    },
    target: {kind: "pull_request", pr_number: 7},
    task: {pr_number: 7},
    review_evidence: {
      head_sha: "abc123",
      base_sha: "base123",
      workspace_head_sha: "abc123",
      publication_workspace_head_sha: "abc123",
      publication_workspace_clean: true,
      changed_file_count: 2,
      expected_changed_file_count: 2,
      incomplete_patch_files: [],
      host_validation_checks: [{
        command: "npm test",
        returncode: 0,
        stdout_sha256: "a".repeat(64),
        stderr_sha256: "b".repeat(64),
      }],
      changed_files: ["src/app.ts", "tests/app.test.ts"],
      changed_file_lines: [{path: "src/app.ts", left_lines: [9], right_lines: [12]}],
    },
  };
}

function signedPublicationMarker(identity: string, createdAt = "", target = "OpenCoven/example#pr:7"): string {
  const proof = createHmac("sha256", "test-webhook-secret").update(`${target}\0${identity}\0${createdAt}`).digest("hex");
  return [
    `<!-- covencat-publication:${identity} -->`,
    createdAt ? `<!-- covencat-task-created:${createdAt} -->` : "",
    `<!-- covencat-publication-proof:${proof} -->`,
  ].filter(Boolean).join("\n");
}

function signedBasePublicationMarker(identity: string, baseSha: string, createdAt = "", target = "OpenCoven/example#pr:7"): string {
  const proof = createHmac("sha256", "test-webhook-secret").update(`${target}\0${identity}\0${createdAt}\0${baseSha}`).digest("hex");
  return [
    `<!-- covencat-publication:${identity} -->`,
    createdAt ? `<!-- covencat-task-created:${createdAt} -->` : "",
    `<!-- covencat-review-base:${baseSha} -->`,
    `<!-- covencat-publication-proof:${proof} -->`,
  ].filter(Boolean).join("\n");
}

function stableCompact(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableCompact).join(",")}]`;
  return `{${Object.entries(value as Record<string, unknown>)
    .filter(([, item]) => item !== undefined)
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([key, item]) => `${JSON.stringify(key)}:${stableCompact(item)}`)
    .join(",")}}`;
}

function publicationIdentityFixture(task: JsonObject, result: JsonObject, includeBase: boolean): string {
  const evidence = task.review_evidence as JsonObject;
  const material: JsonObject = {task_id: task.task_id, head_sha: evidence.head_sha};
  if (includeBase) material.base_sha = evidence.base_sha;
  material.result = result;
  return createHash("sha256").update(stableCompact(material)).digest("hex");
}

function covencatBot(): JsonObject {
  return {login: "covencat[bot]", type: "Bot"};
}

function completeReview(findings: JsonObject[] = []): JsonObject {
  return {
    contract_version: "2",
    status: "success",
    summary: "Reviewed the pull request.",
    pr_body: "",
    files_changed: [],
    commits: [],
    review: {
      mode: "pull_request",
      evidence_status: "complete",
      reviewed_files: ["src/app.ts", "tests/app.test.ts"],
      supporting_files: ["README.md"],
      findings,
      no_findings_reason: findings.length ? null : "The complete changed-file set was reviewed and no actionable defects were found.",
      tests_run: [{command: "npm test", status: "passed", output_summary: "all tests passed"}],
      limitations: [],
    },
  };
}

function prepareReviewWorkspace(config: ReturnType<typeof createConfig>, task: JsonObject): void {
  const root = join(config.workspacesDir, String(task.task_id), "repo");
  for (const path of ["src/app.ts", "tests/app.test.ts", "README.md"]) {
    const target = join(root, path);
    mkdirSync(join(target, ".."), {recursive: true});
    writeFileSync(target, `fixture for ${path}\n`);
  }
}

function githubReadFixture(url: string, init: RequestInit): JsonObject | JsonObject[] | null {
  if (init.method !== "GET") return null;
  if (/\/pulls\/7$/.test(url)) return {head: {sha: "abc123"}, base: {sha: "base123"}};
  return [];
}

function tempStateDir(): string {
  return mkdtempSync(join(tmpdir(), "coven-github-webhook-"));
}

function testConfig(stateDir: string, webhookSecret = "test-webhook-secret") {
  return createConfig(
    {
      COVEN_GITHUB_STATE_DIR: stateDir,
      COVEN_GITHUB_POLICY_PATH: join(stateDir, "policy.json"),
      GITHUB_WEBHOOK_SECRET: webhookSecret,
      COVEN_GITHUB_REVOCATION_EVENTS: "pull-request-and-push-verified",
    },
    process.cwd(),
  );
}

function legacySecretConfig(stateDir: string, webhookSecret = "legacy-webhook-secret") {
  return createConfig(
    {
      COVEN_GITHUB_STATE_DIR: stateDir,
      COVEN_GITHUB_POLICY_PATH: join(stateDir, "policy.json"),
      WEBHOOK_SECRET: webhookSecret,
    },
    process.cwd(),
  );
}

function signature(secret: string, body: Buffer): string {
  return `sha256=${createHmac("sha256", secret).update(body).digest("hex")}`;
}

async function callWebhook(
  body: Buffer,
  headers: Record<string, string> = {},
  contentLength: string | null | "auto" = "auto",
  config = testConfig(tempStateDir()),
) {
  const requestHeaders = new Map<string, string>();
  if (contentLength === "auto") {
    requestHeaders.set("content-length", String(body.length));
  } else if (contentLength !== null) {
    requestHeaders.set("content-length", contentLength);
  }
  for (const [name, value] of Object.entries(headers)) {
    requestHeaders.set(name.toLowerCase(), value);
  }

  return handleRequest(config, {
    method: "POST",
    path: "/webhook",
    headers: requestHeaders,
    rawBody: body,
  });
}

test("webhook rejects missing and invalid signatures", async () => {
  const body = Buffer.from('{"zen":"Keep it logically awesome."}');
  const config = testConfig(tempStateDir());

  const missing = await callWebhook(
    body,
    {"X-GitHub-Event": "ping", "X-GitHub-Delivery": "delivery-1"},
    "auto",
    config,
  );
  assert.equal(missing.status, 401);
  assert.equal(missing.body.error, "missing signature");

  const invalid = await callWebhook(
    body,
    {
      "X-GitHub-Event": "ping",
      "X-GitHub-Delivery": "delivery-2",
      "X-Hub-Signature-256": "sha256=deadbeef",
    },
    "auto",
    config,
  );
  assert.equal(invalid.status, 401);
  assert.equal(invalid.body.error, "invalid signature");
});

test("webhook accepts valid signed ping without runtime", async () => {
  const secret = "valid-webhook-secret";
  const config = testConfig(tempStateDir(), secret);
  const body = Buffer.from('{"zen":"Keep it logically awesome."}');

  const response = await callWebhook(
    body,
    {
      "X-GitHub-Event": "ping",
      "X-GitHub-Delivery": "delivery-3",
      "X-Hub-Signature-256": signature(secret, body),
    },
    "auto",
    config,
  );

  assert.equal(response.status, 200);
  assert.equal(response.body.ok, true);
  assert.equal(response.body.action, "ignored");
  assert.equal(response.body.reason, "no_policy_for_installation_repo");
});

test("HTTP server returns 500 for corrupt persisted state and remains healthy", async () => {
  const secret = "server-state-error-secret";
  const stateDir = tempStateDir();
  const config = testConfig(stateDir, secret);
  const deliveryId = "server-corrupt-delivery";
  const outside = join(mkdtempSync(join(tmpdir(), "coven-corrupt-delivery-")), "delivery.json");
  writeFileSync(outside, "{}\n");
  symlinkSync(outside, join(config.deliveriesDir, `${deliveryId}.json`));
  const server = createWebhookServer(config);
  const originalConsoleError = console.error;
  console.error = () => {};
  try {
    server.listen(0, "127.0.0.1");
    await once(server, "listening");
    const address = server.address() as AddressInfo;
    const body = Buffer.from("{}");
    const failed = await fetch(`http://127.0.0.1:${address.port}/webhook`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-github-event": "ping",
        "x-github-delivery": deliveryId,
        "x-hub-signature-256": signature(secret, body),
      },
      body,
    });
    assert.equal(failed.status, 500);
    assert.deepEqual(await failed.json(), {ok: false, error: "internal server error"});
    const healthy = await fetch(`http://127.0.0.1:${address.port}/healthz`);
    assert.equal(healthy.status, 200);
    assert.deepEqual(await healthy.json(), {ok: true});
  } finally {
    console.error = originalConsoleError;
    server.close();
    if (server.listening) await once(server, "close");
  }
});

test("HTTP server acknowledges a real task before scheduling worker execution", async () => {
  const secret = "async-worker-secret";
  const stateDir = tempStateDir();
  const policyPath = join(stateDir, "policy.json");
  writeFileSync(policyPath, readFileSync(new URL("../config/example-policy.json", import.meta.url)));
  const config = createConfig({
    COVEN_GITHUB_STATE_DIR: stateDir,
    COVEN_GITHUB_POLICY_PATH: policyPath,
    GITHUB_WEBHOOK_SECRET: secret,
  }, process.cwd());
  const scheduled: string[] = [];
  const server = createWebhookServer(config, (taskId) => scheduled.push(taskId));
  try {
    server.listen(0, "127.0.0.1");
    await once(server, "listening");
    const address = server.address() as AddressInfo;
    const body = Buffer.from(JSON.stringify({
      action: "labeled",
      installation: {id: 123456},
      repository: {id: 987654321, full_name: "OpenCoven/example", default_branch: "main"},
      issue: {number: 42, title: "Queue safely", body: "Do not block the listener.", labels: [{name: "coven:fix"}]},
    }));
    const response = await fetch(`http://127.0.0.1:${address.port}/webhook`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-github-event": "issues",
        "x-github-delivery": "async-worker-delivery",
        "x-hub-signature-256": signature(secret, body),
      },
      body,
    });
    assert.equal(response.status, 200);
    const responseBody = await response.json() as JsonObject;
    assert.equal(responseBody.state, "queued");
    assert.equal(responseBody.queued, true);
    assert.deepEqual(scheduled, ["async-worker-delivery"]);
    const persisted = JSON.parse(readFileSync(join(config.tasksDir, "async-worker-delivery.json"), "utf8")) as JsonObject;
    assert.equal(persisted.state, "queued");
    const healthy = await fetch(`http://127.0.0.1:${address.port}/healthz`);
    assert.equal(healthy.status, 200);
  } finally {
    server.close();
    if (server.listening) await once(server, "close");
  }
});

test("default task worker drains an acknowledged task without blocking the server", async () => {
  const secret = "default-worker-secret";
  const stateDir = tempStateDir();
  const policyPath = join(stateDir, "policy.json");
  writeFileSync(policyPath, readFileSync(new URL("../config/example-policy.json", import.meta.url)));
  const config = createConfig({
    COVEN_GITHUB_STATE_DIR: stateDir,
    COVEN_GITHUB_POLICY_PATH: policyPath,
    GITHUB_WEBHOOK_SECRET: secret,
  }, process.cwd());
  const server = createWebhookServer(config);
  try {
    server.listen(0, "127.0.0.1");
    await once(server, "listening");
    const address = server.address() as AddressInfo;
    const body = Buffer.from(JSON.stringify({
      action: "labeled",
      installation: {id: 123456},
      repository: {id: 987654321, full_name: "OpenCoven/example", default_branch: "main"},
      issue: {number: 43, title: "Worker execution", body: "Fail closed in the worker.", labels: [{name: "coven:fix"}]},
    }));
    const response = await fetch(`http://127.0.0.1:${address.port}/webhook`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-github-event": "issues",
        "x-github-delivery": "default-worker-delivery",
        "x-hub-signature-256": signature(secret, body),
      },
      body,
    });
    assert.equal(response.status, 200);
    assert.equal((await response.json() as JsonObject).state, "queued");
    const taskFile = join(config.tasksDir, "default-worker-delivery.json");
    let persisted: JsonObject = {};
    for (let attempt = 0; attempt < 100; attempt += 1) {
      persisted = JSON.parse(readFileSync(taskFile, "utf8")) as JsonObject;
      if (persisted.state !== "queued" && persisted.state !== "running") break;
      await new Promise((resolveDelay) => setTimeout(resolveDelay, 20));
    }
    assert.equal(persisted.state, "blocked");
    assert.equal(persisted.failure_category, "runtime_isolation_unavailable");
    const healthy = await fetch(`http://127.0.0.1:${address.port}/healthz`);
    assert.equal(healthy.status, 200);
  } finally {
    server.close();
    if (server.listening) await once(server, "close");
  }
});

test("task supervisor keeps retrying a worker that exits twice and then recovers", async () => {
  const stateDir = tempStateDir();
  const config = testConfig(stateDir);
  const taskId = "flaky-worker-supervision";
  writeFileSync(join(config.tasksDir, `${taskId}.json`), JSON.stringify({
    task_id: taskId,
    state: "queued",
    task: {kind: "respond_to_mention"},
  }));
  const counterPath = join(stateDir, "flaky-worker-count");
  const workerPath = join(stateDir, "flaky-worker.mjs");
  writeFileSync(workerPath, [
    'import {existsSync, readFileSync, writeFileSync} from "node:fs";',
    `const counterPath = ${JSON.stringify(counterPath)};`,
    'process.once("message", () => {',
    '  const count = (existsSync(counterPath) ? Number(readFileSync(counterPath, "utf8")) : 0) + 1;',
    '  writeFileSync(counterPath, String(count));',
    '  if (count < 3) process.exit(17);',
    '  process.send?.({ok: true, state: "completed"}, () => process.disconnect());',
    '});',
  ].join("\n"));
  const schedule = createWorkerTaskScheduler(config, {
    workerUrl: pathToFileURL(workerPath),
    retryBaseMs: 5,
    retryMaxMs: 20,
  });
  const originalConsoleError = console.error;
  console.error = () => {};
  try {
    schedule(taskId);
    const deadline = Date.now() + 2_000;
    while ((!existsSync(counterPath) || Number(readFileSync(counterPath, "utf8")) < 3) && Date.now() < deadline) {
      await new Promise((resolveDelay) => setTimeout(resolveDelay, 10));
    }
    assert.equal(Number(readFileSync(counterPath, "utf8")), 3);
    await new Promise((resolveDelay) => setTimeout(resolveDelay, 50));
    assert.equal(Number(readFileSync(counterPath, "utf8")), 3);
  } finally {
    console.error = originalConsoleError;
  }
});

test("webhook reads body when content length is missing", async () => {
  const secret = "missing-length-secret";
  const config = testConfig(tempStateDir(), secret);
  const body = Buffer.from('{"zen":"Keep it logically awesome."}');

  const response = await callWebhook(
    body,
    {
      "X-GitHub-Event": "ping",
      "X-GitHub-Delivery": "delivery-missing-length",
      "X-Hub-Signature-256": signature(secret, body),
    },
    null,
    config,
  );

  assert.equal(response.status, 200);
  assert.equal(response.body.ok, true);
});

test("webhook reads body when content length is unparsable", async () => {
  const secret = "bad-length-secret";
  const config = testConfig(tempStateDir(), secret);
  const body = Buffer.from('{"zen":"Keep it logically awesome."}');

  const response = await callWebhook(
    body,
    {
      "X-GitHub-Event": "ping",
      "X-GitHub-Delivery": "delivery-bad-length",
      "X-Hub-Signature-256": signature(secret, body),
    },
    "not-a-number",
    config,
  );

  assert.equal(response.status, 200);
  assert.equal(response.body.ok, true);
});

test("webhook treats partially numeric content length as unparsable", async () => {
  const secret = "partial-length-secret";
  const config = testConfig(tempStateDir(), secret);
  const body = Buffer.from('{"zen":"Keep it logically awesome."}');

  const response = await callWebhook(
    body,
    {
      "X-GitHub-Event": "ping",
      "X-GitHub-Delivery": "delivery-partial-length",
      "X-Hub-Signature-256": signature(secret, body),
    },
    "12oops",
    config,
  );

  assert.equal(response.status, 200);
  assert.equal(response.body.ok, true);
});

test("webhook treats zero content length as empty body", async () => {
  const secret = "zero-length-secret";
  const config = testConfig(tempStateDir(), secret);

  const response = await callWebhook(
    Buffer.from('{"zen":"Keep it logically awesome."}'),
    {
      "X-GitHub-Event": "ping",
      "X-GitHub-Delivery": "delivery-zero-length",
      "X-Hub-Signature-256": signature(secret, Buffer.alloc(0)),
    },
    "0",
    config,
  );

  assert.equal(response.status, 400);
  assert.equal(response.body.error, "invalid json");
});

test("webhook rejects oversized content length before signature check", async () => {
  const response = await callWebhook(
    Buffer.alloc(0),
    {
      "X-GitHub-Event": "ping",
      "X-GitHub-Delivery": "delivery-large-body",
      "X-Hub-Signature-256": "sha256=deadbeef",
    },
    String(10 * 1024 * 1024 + 1),
  );

  assert.equal(response.status, 413);
  assert.equal(response.body.error, "payload too large");
});

test("webhook signature allows surrounding whitespace", async () => {
  const secret = "whitespace-secret";
  const config = testConfig(tempStateDir(), secret);
  const body = Buffer.from('{"zen":"Keep it logically awesome."}');

  const response = await callWebhook(
    body,
    {
      "X-GitHub-Event": "ping",
      "X-GitHub-Delivery": "delivery-whitespace-signature",
      "X-Hub-Signature-256": ` ${signature(secret, body)} `,
    },
    "auto",
    config,
  );

  assert.equal(response.status, 200);
  assert.equal(response.body.ok, true);
});

test("webhook reports missing secret as server misconfiguration", async () => {
  const config = testConfig(tempStateDir(), "");
  const body = Buffer.from('{"zen":"Keep it logically awesome."}');

  const response = await callWebhook(
    body,
    {
      "X-GitHub-Event": "ping",
      "X-GitHub-Delivery": "delivery-missing-secret",
      "X-Hub-Signature-256": signature("ignored", body),
    },
    "auto",
    config,
  );

  assert.equal(response.status, 500);
  assert.equal(response.body.error, "webhook secret not configured");
});

test("webhook secret supports smoke script environment name", async () => {
  const secret = "legacy-webhook-secret";
  const config = legacySecretConfig(tempStateDir(), secret);
  const body = Buffer.from('{"zen":"Keep it logically awesome."}');

  const response = await callWebhook(
    body,
    {
      "X-GitHub-Event": "ping",
      "X-GitHub-Delivery": "delivery-legacy",
      "X-Hub-Signature-256": signature(secret, body),
    },
    "auto",
    config,
  );

  assert.equal(response.status, 200);
  assert.equal(response.body.ok, true);
});

test("config accepts an inline GitHub App private key from env", () => {
  const config = createConfig(
    {
      COVEN_GITHUB_STATE_DIR: tempStateDir(),
      GITHUB_APP_PRIVATE_KEY: "-----BEGIN PRIVATE KEY-----\nexample\n-----END PRIVATE KEY-----",
    },
    process.cwd(),
  );

  assert.equal(config.privateKeyPem, "-----BEGIN PRIVATE KEY-----\nexample\n-----END PRIVATE KEY-----");
});

test("runtime token is restricted to one repository with contents read authority", () => {
  assert.deepEqual(runtimeInstallationTokenRequest(987654321), {
    repository_ids: [987654321],
    permissions: {contents: "read"},
  });
  assert.deepEqual(reviewContextInstallationTokenRequest(987654321), {
    repository_ids: [987654321],
    permissions: {contents: "read", pull_requests: "read"},
  });
  assert.deepEqual(publicationInstallationTokenRequest(987654321), {
    repository_ids: [987654321],
    permissions: {issues: "write", pull_requests: "write"},
  });
  assert.throws(() => runtimeInstallationTokenRequest(undefined), /valid repository ID/);
  assert.throws(() => publicationInstallationTokenRequest("not-a-repository"), /valid repository ID/);
});

test("real tasks fail closed before GitHub calls when runtime isolation is disabled", async () => {
  const secret = "isolation-gate-secret";
  const stateDir = tempStateDir();
  const policyPath = join(stateDir, "policy.json");
  writeFileSync(policyPath, readFileSync(new URL("../config/example-policy.json", import.meta.url)));
  const config = createConfig({
    COVEN_GITHUB_STATE_DIR: stateDir,
    COVEN_GITHUB_POLICY_PATH: policyPath,
    GITHUB_WEBHOOK_SECRET: secret,
  }, process.cwd());
  const body = Buffer.from(JSON.stringify({
    action: "labeled",
    installation: {id: 123456},
    repository: {
      id: 987654321,
      full_name: "OpenCoven/example",
      clone_url: "https://github.com/OpenCoven/example.git",
      default_branch: "main",
    },
    issue: {
      number: 42,
      title: "Do not execute directly",
      body: "This must be sandboxed.",
      labels: [{name: "coven:fix"}],
    },
  }));
  let githubCalls = 0;
  const response = await withGithubApiMock(() => {
    githubCalls += 1;
    throw new Error("GitHub must not be called before isolation succeeds");
  }, async () => {
    const accepted = await callWebhook(body, {
      "X-GitHub-Event": "issues",
      "X-GitHub-Delivery": "delivery-isolation-disabled",
      "X-Hub-Signature-256": signature(secret, body),
    }, "auto", config);
    assert.equal(accepted.body.state, "queued");
    assert.equal(accepted.body.queued, true);
    await runTask(config, "delivery-isolation-disabled");
    return accepted;
  });

  assert.equal(response.status, 200);
  assert.equal(response.body.state, "queued");
  assert.equal(githubCalls, 0);
  const task = JSON.parse(readFileSync(join(stateDir, "tasks", "delivery-isolation-disabled.json"), "utf8")) as JsonObject;
  assert.equal(task.state, "blocked");
  assert.equal(task.failure_category, "runtime_isolation_unavailable");
  assert.equal(task.publication_state, "not_started");
  assert.equal(task.attempts, 0);
});

test("configuration rejects a state root that is a symbolic link", () => {
  const parent = mkdtempSync(join(tmpdir(), "coven-state-parent-"));
  const outside = mkdtempSync(join(tmpdir(), "coven-state-outside-"));
  const stateLink = join(parent, "state");
  symlinkSync(outside, stateLink, "dir");
  assert.throws(() => testConfig(stateLink), /must be a real directory/);
});

test("configuration rejects group or world access to the state root", () => {
  if (typeof process.getuid !== "function") return;
  const stateDir = tempStateDir();
  chmodSync(stateDir, 0o777);
  assert.throws(() => testConfig(stateDir), /must not grant group or world access/);
});

test("configuration rejects a state root beneath an unsafe writable ancestor", () => {
  if (typeof process.getuid !== "function") return;
  const parent = mkdtempSync(join(tmpdir(), "coven-state-unsafe-parent-"));
  chmodSync(parent, 0o777);
  try {
    assert.throws(
      () => testConfig(join(parent, "state")),
      /must not be beneath a group- or world-writable non-sticky directory/,
    );
  } finally {
    chmodSync(parent, 0o700);
    rmSync(parent, {recursive: true, force: true});
  }
});

test("task startup refuses legacy attempt and workspace symlinks before writing through them", async () => {
  const secret = "legacy-state-symlink-secret";
  const deliveryId = "delivery-legacy-state-symlink";
  const payload = Buffer.from(JSON.stringify({
    action: "labeled",
    installation: {id: 123456},
    repository: {
      id: 987654321,
      full_name: "OpenCoven/example",
      clone_url: "https://github.com/OpenCoven/example.git",
      default_branch: "main",
    },
    issue: {number: 42, title: "Do not follow state links", body: "Review safely.", labels: [{name: "coven:fix"}]},
  }));

  for (const location of ["attempt-task-root", "workspace-attempt"] as const) {
    const stateDir = tempStateDir();
    const policyPath = join(stateDir, "policy.json");
    writeFileSync(policyPath, readFileSync(new URL("../config/example-policy.json", import.meta.url)));
    const config = createConfig({
      COVEN_GITHUB_STATE_DIR: stateDir,
      COVEN_GITHUB_POLICY_PATH: policyPath,
      GITHUB_WEBHOOK_SECRET: secret,
      COVEN_GITHUB_DEMO_MODE: "1",
    }, process.cwd());
    const outside = mkdtempSync(join(tmpdir(), "coven-state-link-target-"));
    writeFileSync(join(outside, "sentinel"), "unchanged\n");
    if (location === "attempt-task-root") {
      symlinkSync(outside, join(config.attemptsDir, deliveryId), "dir");
    } else {
      mkdirSync(join(config.workspacesDir, deliveryId));
      symlinkSync(outside, join(config.workspacesDir, deliveryId, "1"), "dir");
    }

    const response = await callWebhook(payload, {
      "X-GitHub-Event": "issues",
      "X-GitHub-Delivery": deliveryId,
      "X-Hub-Signature-256": signature(secret, payload),
    }, "auto", config);
    const task = JSON.parse(readFileSync(join(config.tasksDir, `${deliveryId}.json`), "utf8")) as JsonObject;
    assert.equal(response.body.state, "blocked");
    assert.equal(task.failure_category, "state_storage_untrusted");
    assert.deepEqual(readdirSync(outside), ["sentinel"]);
    assert.equal(readFileSync(join(outside, "sentinel"), "utf8"), "unchanged\n");
  }
});

test("runtime sandbox exposes only explicit mounts and runtime env omits GitHub credentials", () => {
  const stateDir = tempStateDir();
  const rootfs = mkdtempSync(join(tmpdir(), "coven-runtime-rootfs-"));
  const bwrap = join(mkdtempSync(join(tmpdir(), "coven-bwrap-")), "bwrap");
  for (const path of ["usr/local/bin/coven-code", "usr/bin/git", "bin/sh", "bin/true"]) {
    const target = join(rootfs, path);
    mkdirSync(join(target, ".."), {recursive: true});
    writeFileSync(target, "#!/bin/sh\nexit 0\n", {mode: 0o755});
  }
  writeFileSync(bwrap, "#!/bin/sh\nexit 0\n", {mode: 0o755});
  const config = createConfig({
    COVEN_GITHUB_STATE_DIR: stateDir,
    COVEN_GITHUB_POLICY_PATH: join(stateDir, "policy.json"),
    COVEN_RUNTIME_ISOLATION: "bwrap",
    COVEN_RUNTIME_EXTERNAL_ISOLATION: "network-egress-and-resource-limits-verified",
    COVEN_BWRAP_BIN: bwrap,
    COVEN_RUNTIME_ROOTFS: rootfs,
    COVEN_CODE_BIN: "/usr/local/bin/coven-code",
  }, process.cwd());
  if (typeof process.getuid === "function" && process.getuid() !== 0) {
    assert.match(String(runtimeIsolationIssue(config)), /root-owned/);
  } else {
    assert.equal(runtimeIsolationIssue(config), null);
  }
  const workspace = join(stateDir, "workspaces", "task", "repo");
  const inputDir = join(stateDir, "attempts", "task", "1", "input");
  const outputDir = join(stateDir, "attempts", "task", "1", "output");
  mkdirSync(join(workspace, ".git"), {recursive: true});
  mkdirSync(inputDir, {recursive: true});
  mkdirSync(outputDir, {recursive: true});
  const args = runtimeSandboxArgs(config, {workspace, inputDir, outputDir}, ["/usr/local/bin/coven-code", "--headless"]);
  const argv = args.join("\0");
  assert.equal(args[0], bwrap);
  assert.match(argv, new RegExp(`--ro-bind\\0${inputDir}\\0/run/coven/input`));
  assert.match(argv, new RegExp(`--bind\\0${workspace}\\0/workspace`));
  assert.match(argv, new RegExp(`--bind\\0${outputDir}\\0/run/coven/output`));
  assert.ok(args.includes("--unshare-net"));
  assert.ok(args.includes("/workspace/.git"));
  assert.equal(args.includes(config.privateKeyPath), false);
  assert.equal(args.includes(config.codexTokensPath), false);
  const runtimeEnv = runtimeProcessEnvironment({
    PATH: "/host/bin",
    HOME: "/host/home",
    GITHUB_APP_PRIVATE_KEY: "private",
    GITHUB_WEBHOOK_SECRET: "webhook",
    COVEN_GIT_TOKEN: "github",
    GIT_ASKPASS: "/tmp/askpass",
    SSH_AUTH_SOCK: "/tmp/agent",
  }, "codex-only");
  assert.equal(runtimeEnv.HOME, "/home/coven");
  assert.equal(runtimeEnv.OPENAI_API_KEY, "codex-only");
  for (const key of ["GITHUB_APP_PRIVATE_KEY", "GITHUB_WEBHOOK_SECRET", "COVEN_GIT_TOKEN", "GIT_ASKPASS", "SSH_AUTH_SOCK"]) {
    assert.equal(runtimeEnv[key], undefined);
  }
});

test("runtime result reader rejects symlinks and oversized artifacts", () => {
  const root = mkdtempSync(join(tmpdir(), "coven-runtime-result-"));
  const valid = join(root, "valid.json");
  writeFileSync(valid, JSON.stringify({status: "success"}));
  assert.deepEqual(readBoundedRuntimeResult(valid), {status: "success"});
  const symlink = join(root, "symlink.json");
  symlinkSync(valid, symlink);
  assert.throws(() => readBoundedRuntimeResult(symlink));
  const oversized = join(root, "oversized.json");
  writeFileSync(oversized, `{"data":"${"x".repeat(2 * 1024 * 1024)}"}`);
  assert.throws(() => readBoundedRuntimeResult(oversized), /exceeds/);
});

test("missing familiar policy does not fall back to hardcoded installation", () => {
  const task = buildTaskFromEvent(
    "issues",
    "delivery-4",
    {
      action: "opened",
      installation: {id: 111},
      repository: {
        id: 222,
        full_name: "OpenCoven/example",
        clone_url: "https://github.com/OpenCoven/example.git",
        default_branch: "main",
      },
      issue: {number: 7, title: "Fix it", body: "Please fix it."},
    } as JsonObject,
    {
      trigger_labels: ["coven:fix"],
      bot_usernames: ["coven-github[bot]"],
      publication: {mode: "record_only"},
    } as JsonObject,
  );

  assert.equal(task.state, "ignored");
  assert.equal(task.ignored_reason, "missing_familiar_policy");
});

test("example policy routes a labeled issue to the configured familiar", () => {
  const policyFile = new URL("../config/example-policy.json", import.meta.url);
  const policyRoot = JSON.parse(readFileSync(policyFile, "utf8")) as JsonObject;
  const installation = (policyRoot.installations as JsonObject)["123456"] as JsonObject;
  const policy = ((installation.repositories as JsonObject)["987654321"]) as JsonObject;

  const task = buildTaskFromEvent(
    "issues",
    "delivery-example-policy",
    {
      action: "labeled",
      installation: {id: 123456},
      repository: {
        id: 987654321,
        full_name: "OpenCoven/example",
        clone_url: "https://github.com/OpenCoven/example.git",
        default_branch: "main",
      },
      issue: {
        number: 42,
        title: "Wire the app",
        body: "Make the first app route functional.",
        labels: [{name: "coven:fix"}],
      },
    } as JsonObject,
    policy,
  );

  assert.equal(task.state, "queued");
  assert.equal(task.trigger, "issue_mention");
  assert.deepEqual(task.task, {
    kind: "fix_issue",
    issue_number: 42,
    issue_title: "Wire the app",
    issue_body: "Make the first app route functional.",
  });
  assert.deepEqual(task.familiar, {
    id: "cody",
    display_name: "Cody",
    model: "openai/gpt-5.5",
    skills: ["systematic-debugging", "test-driven-development"],
  });
});

test("routing enforces exact enabled event actions before spending compute", async () => {
  const secret = "enabled-trigger-secret";
  const stateDir = tempStateDir();
  const policyPath = join(stateDir, "policy.json");
  writeFileSync(policyPath, readFileSync(new URL("../config/example-policy.json", import.meta.url)));
  const config = createConfig({
    COVEN_GITHUB_STATE_DIR: stateDir,
    COVEN_GITHUB_POLICY_PATH: policyPath,
    GITHUB_WEBHOOK_SECRET: secret,
    COVEN_GITHUB_DEMO_MODE: "1",
  }, process.cwd());
  const payload = Buffer.from(JSON.stringify({
    action: "opened",
    installation: {id: 123456},
    repository: {id: 987654321, full_name: "OpenCoven/example"},
    issue: {number: 91, title: "An ordinary issue", body: "This action is not enabled.", labels: []},
  }));
  const response = await callWebhook(payload, {
    "X-GitHub-Event": "issues",
    "X-GitHub-Delivery": "disabled-issues-opened",
    "X-Hub-Signature-256": signature(secret, payload),
  }, "auto", config);
  assert.equal(response.body.action, "ignored");
  assert.equal(response.body.reason, "trigger_not_enabled");
  assert.equal(response.body.trigger, "issues.opened");
  assert.equal(existsSync(join(config.tasksDir, "disabled-issues-opened.json")), false);

  const policyRoot = JSON.parse(readFileSync(policyPath, "utf8")) as JsonObject;
  const installation = (policyRoot.installations as JsonObject)["123456"] as JsonObject;
  const repoPolicy = (installation.repositories as JsonObject)["987654321"] as JsonObject;
  const assigned = buildTaskFromEvent("issues", "assigned-elsewhere", {
    action: "assigned",
    installation: {id: 123456},
    repository: {id: 987654321, full_name: "OpenCoven/example"},
    assignee: {login: "human-maintainer"},
    issue: {number: 92, assignee: {login: "human-maintainer"}},
  }, repoPolicy);
  assert.equal(assigned.state, "ignored");
  assert.equal(assigned.ignored_reason, "issue_assignment_not_for_bot");
});

test("unsafe native-review policy returns retryable 503 without claiming the delivery", async () => {
  const secret = "unsafe-native-policy-secret";
  const stateDir = tempStateDir();
  const policyPath = join(stateDir, "policy.json");
  const policy = JSON.parse(readFileSync(new URL("../config/example-policy.json", import.meta.url), "utf8")) as JsonObject;
  const installation = (policy.installations as JsonObject)["123456"] as JsonObject;
  const repoPolicy = (installation.repositories as JsonObject)["987654321"] as JsonObject;
  repoPolicy.publication = {mode: "comment"};
  repoPolicy.enabled_triggers = (repoPolicy.enabled_triggers as JsonValue[]).filter((trigger) => trigger !== "push");
  writeFileSync(policyPath, JSON.stringify(policy));
  const config = createConfig({
    COVEN_GITHUB_STATE_DIR: stateDir,
    COVEN_GITHUB_POLICY_PATH: policyPath,
    GITHUB_WEBHOOK_SECRET: secret,
    COVEN_GITHUB_DEMO_MODE: "1",
  }, process.cwd());
  const body = Buffer.from(JSON.stringify({
    action: "labeled",
    installation: {id: 123456},
    repository: {id: 987654321, full_name: "OpenCoven/example", default_branch: "main"},
    issue: {number: 93, title: "Retry after policy repair", body: "Do not claim this delivery yet.", labels: [{name: "coven:fix"}]},
  }));
  const headers = {
    "X-GitHub-Event": "issues",
    "X-GitHub-Delivery": "unsafe-policy-retry",
    "X-Hub-Signature-256": signature(secret, body),
  };
  const rejected = await callWebhook(body, headers, "auto", config);
  assert.equal(rejected.status, 503);
  assert.equal(rejected.body.action, "retry");
  assert.equal(rejected.body.reason, "native_review_policy_unsafe");
  assert.equal(existsSync(join(config.deliveriesDir, "unsafe-policy-retry.json")), false);

  (repoPolicy.enabled_triggers as JsonValue[]).push("push");
  writeFileSync(policyPath, JSON.stringify(policy));
  const accepted = await callWebhook(body, headers, "auto", config);
  assert.equal(accepted.status, 200);
  assert.equal(accepted.body.action, "accepted");
  assert.equal(existsSync(join(config.deliveriesDir, "unsafe-policy-retry.json")), true);
});

test("native review routing requires explicit live revocation-event verification", async () => {
  const secret = "revocation-event-attestation-secret";
  const stateDir = tempStateDir();
  const policyPath = join(stateDir, "policy.json");
  const policy = JSON.parse(readFileSync(new URL("../config/example-policy.json", import.meta.url), "utf8")) as JsonObject;
  const installation = (policy.installations as JsonObject)["123456"] as JsonObject;
  const repoPolicy = (installation.repositories as JsonObject)["987654321"] as JsonObject;
  repoPolicy.publication = {mode: "comment"};
  writeFileSync(policyPath, JSON.stringify(policy));
  const config = createConfig({
    COVEN_GITHUB_STATE_DIR: stateDir,
    COVEN_GITHUB_POLICY_PATH: policyPath,
    GITHUB_WEBHOOK_SECRET: secret,
  }, process.cwd());
  const body = Buffer.from(JSON.stringify({
    action: "labeled",
    installation: {id: 123456},
    repository: {id: 987654321, full_name: "OpenCoven/example", default_branch: "main"},
    issue: {number: 94, title: "Verify App events", body: "Fail closed first.", labels: [{name: "coven:fix"}]},
  }));
  const headers = {
    "X-GitHub-Event": "issues",
    "X-GitHub-Delivery": "revocation-events-unverified",
    "X-Hub-Signature-256": signature(secret, body),
  };
  const rejected = await callWebhook(body, headers, "auto", config);
  assert.equal(rejected.status, 503);
  assert.match(String(rejected.body.error || ""), /COVEN_GITHUB_REVOCATION_EVENTS/);
  assert.equal(existsSync(join(config.deliveriesDir, "revocation-events-unverified.json")), false);

  config.revocationEventsVerified = true;
  const accepted = await callWebhook(body, headers, "auto", config);
  assert.equal(accepted.status, 200);
  assert.equal(accepted.body.state, "queued");
});

test("pull request revision tasks dismiss stale signed decisive reviews", async () => {
  const stateDir = tempStateDir();
  const {privateKey} = generateKeyPairSync("rsa", {modulusLength: 2048});
  const config = createConfig({
    COVEN_GITHUB_STATE_DIR: stateDir,
    COVEN_GITHUB_POLICY_PATH: join(stateDir, "policy.json"),
    GITHUB_WEBHOOK_SECRET: "test-webhook-secret",
    GITHUB_APP_ID: "1234",
    COVEN_GITHUB_REVOCATION_EVENTS: "pull-request-and-push-verified",
    GITHUB_APP_PRIVATE_KEY: privateKey.export({type: "pkcs8", format: "pem"}).toString(),
  }, process.cwd());
  const policy: JsonObject = {
    familiar: {id: "reviewer"},
    publication: {mode: "comment"},
    bot_usernames: ["covencat[bot]"],
    enabled_triggers: ["pull_request.synchronize", "pull_request.edited", "pull_request.reopened", "push"],
  };
  const task = buildTaskFromEvent("pull_request", "reconcile-stale-review", {
    action: "synchronize",
    installation: {id: 123456},
    repository: {id: 987654321, full_name: "OpenCoven/example"},
    pull_request: {
      number: 7,
      head: {sha: "new-head", ref: "feature"},
      base: {sha: "base123", ref: "main"},
    },
  }, policy);
  task.policy_snapshot = {
    bot_usernames: ["covencat[bot]"],
    enabled_triggers: ["pull_request.synchronize", "pull_request.edited", "pull_request.reopened", "push"],
    publication: {mode: "comment"},
  };
  writeFileSync(join(config.tasksDir, `${task.task_id}.json`), JSON.stringify(task));
  const oldBody = `Old decisive review\n\n${signedBasePublicationMarker("d".repeat(64), "old-base", "2026-07-14T00:00:00Z")}`;
  const mutations: Array<{url: string; body: JsonObject}> = [];
  await withGithubApiMock((url, init) => {
    if (/\/app\/installations\/123456\/access_tokens$/.test(url)) {
      const request = JSON.parse(String(init.body)) as JsonObject;
      assert.deepEqual(request.repository_ids, [987654321]);
      assert.deepEqual(request.permissions, {issues: "write", pull_requests: "write"});
      return {token: "scoped-publication-token"};
    }
    if (/\/pulls\/7$/.test(url)) return {head: {sha: "new-head"}, base: {sha: "base123"}};
    if (init.method === "GET" && /\/pulls\/7\/reviews(?:\?|$)/.test(url)) return [{
      id: 760,
      state: "APPROVED",
      commit_id: "old-head",
      body: oldBody,
      html_url: "https://github.com/OpenCoven/example/pull/7#pullrequestreview-760",
      user: covencatBot(),
    }];
    if (init.method === "GET") return [];
    const body = init.body ? JSON.parse(String(init.body)) as JsonObject : {};
    mutations.push({url, body});
    return {id: 760, state: "DISMISSED", body: body.body || oldBody, html_url: "https://github.com/OpenCoven/example/pull/7#pullrequestreview-760"};
  }, async () => runTask(config, String(task.task_id)));
  const persisted = JSON.parse(readFileSync(join(config.tasksDir, `${task.task_id}.json`), "utf8")) as JsonObject;
  assert.equal(persisted.state, "completed");
  assert.equal(persisted.publication_state, "stale_decisive_reviews_dismissed");
  assert.deepEqual(persisted.dismissed_review_ids, [760]);
  assert.equal(mutations.length, 2);
  assert.match(mutations[0].url, /\/reviews\/760\/dismissals$/);
  assert.equal(mutations[0].body.event, "DISMISS");
  assert.match(mutations[1].url, /\/reviews\/760$/);
  assert.match(String(mutations[1].body.body || ""), /dismissed automatically/);
});

test("demo mode handles a signed labeled issue without external GitHub calls", async () => {
  const secret = "demo-route-secret";
  const stateDir = tempStateDir();
  const policyPath = join(stateDir, "policy.json");
  writeFileSync(
    policyPath,
    readFileSync(new URL("../config/example-policy.json", import.meta.url)),
  );
  const config = createConfig(
    {
      COVEN_GITHUB_DEMO_MODE: "1",
      COVEN_GITHUB_STATE_DIR: stateDir,
      COVEN_GITHUB_POLICY_PATH: policyPath,
      GITHUB_WEBHOOK_SECRET: secret,
    },
    process.cwd(),
  );
  const body = Buffer.from(JSON.stringify({
    action: "labeled",
    installation: {id: 123456},
    repository: {
      id: 987654321,
      full_name: "OpenCoven/example",
      clone_url: "https://github.com/OpenCoven/example.git",
      default_branch: "main",
    },
    issue: {
      number: 42,
      title: "Wire the app",
      body: "Make the first app route functional.",
      labels: [{name: "coven:fix"}],
    },
  }));

  const response = await callWebhook(
    body,
    {
      "X-GitHub-Event": "issues",
      "X-GitHub-Delivery": "delivery-demo-mode",
      "X-Hub-Signature-256": signature(secret, body),
    },
    "auto",
    config,
  );

  assert.equal(response.status, 200);
  assert.equal(response.body.action, "accepted");
  assert.equal(response.body.state, "completed");

  const taskPath = join(stateDir, "tasks", "delivery-demo-mode.json");
  assert.equal(existsSync(taskPath), true);
  const task = JSON.parse(readFileSync(taskPath, "utf8")) as JsonObject;
  assert.equal(task.state, "completed");
  assert.equal(task.demo_mode, true);
  assert.equal(task.publication_state, "demo_mode_no_github_calls");
  assert.equal(existsSync(String(task.session_brief_path)), true);
  assert.equal(existsSync(String(task.result_path)), true);
});

test("worker recovery reclaims a dead-process lease and retries an interrupted task", async () => {
  const stateDir = tempStateDir();
  const config = createConfig({
    COVEN_GITHUB_STATE_DIR: stateDir,
    COVEN_GITHUB_POLICY_PATH: join(stateDir, "policy.json"),
    GITHUB_WEBHOOK_SECRET: "worker-recovery-secret",
    COVEN_GITHUB_DEMO_MODE: "1",
  }, process.cwd());
  const taskId = "interrupted-worker-task";
  writeFileSync(join(config.tasksDir, `${taskId}.json`), JSON.stringify({
    task_id: taskId,
    state: "running",
    attempts: 1,
    repository: "OpenCoven/example",
    familiar: {id: "cody", display_name: "Cody"},
    publication: {mode: "record_only"},
    task: {kind: "fix_issue", issue_number: 42},
  }));
  const lockName = `${createHash("sha256").update(`execution:${taskId}`).digest("hex").slice(0, 24)}.lock`;
  const lockPath = join(config.publicationsDir, lockName);
  mkdirSync(lockPath, {mode: 0o700});
  const bootId = readFileSync("/proc/sys/kernel/random/boot_id", "utf8").trim();
  writeFileSync(join(lockPath, "owner"), JSON.stringify({
    owner: "dead-owner",
    pid: 2_000_000_000,
    hostname: hostname(),
    boot_id: bootId,
    process_start: "1",
  }), {mode: 0o600});
  const recovered = await runTask(config, taskId);
  assert.equal(recovered.state, "completed");
  assert.equal(recovered.attempts, 2);
  assert.equal(recovered.recovered_from_interrupted_worker, true);
  assert.equal(existsSync(lockPath), false);
});

test("publishes a native change-request review with inline findings and skips a retry", async () => {
  const stateDir = tempStateDir();
  const config = testConfig(stateDir);
  const task = reviewTask();
  prepareReviewWorkspace(config, task);
  const resultPath = join(stateDir, "result.json");
  writeFileSync(resultPath, JSON.stringify(completeReview([{
    severity: "high",
    file: "src/app.ts",
    line: 12,
    title: "Validate input",
    body: "The request is accepted without validation.",
    recommendation: "Reject malformed input.",
  }])));
  const calls: Array<{url: string; init: RequestInit}> = [];
  let publishedBody = "";

  await withGithubApiMock((url, init) => {
    calls.push({url, init});
    if (init.method === "GET" && /\/pulls\/7\/reviews\/101$/.test(url)) {
      return {id: 101, state: "CHANGES_REQUESTED", body: publishedBody, html_url: "https://github.com/OpenCoven/example/pull/7#pullrequestreview-101", user: covencatBot()};
    }
    const read = githubReadFixture(url, init);
    if (read) return read;
    if (init.method === "POST" && /\/pulls\/7\/reviews$/.test(url)) {
      publishedBody = String((JSON.parse(String(init.body)) as JsonObject).body || "");
    }
    return {id: 101, html_url: "https://github.com/OpenCoven/example/pull/7#pullrequestreview-101"};
  }, async () => {
    await publishResultIfConfigured(config, task, resultPath, "token");
    await publishResultIfConfigured(config, task, resultPath, "token");
  });

  const mutations = calls.filter((call) => call.init.method !== "GET");
  assert.equal(mutations.length, 2);
  assert.match(mutations[0].url, /\/pulls\/7\/reviews$/);
  const draft = JSON.parse(String(mutations[0].init.body)) as JsonObject;
  assert.equal(draft.event, undefined);
  assert.equal(draft.commit_id, "abc123");
  assert.equal((draft.comments as JsonObject[]).length, 1);
  assert.match(mutations[1].url, /\/pulls\/7\/reviews\/101\/events$/);
  const submission = JSON.parse(String(mutations[1].init.body)) as JsonObject;
  assert.equal(submission.event, "REQUEST_CHANGES");
  assert.ok(mutations[0].init.signal instanceof AbortSignal);
  assert.ok(calls.some((call) => call.init.method === "GET" && /\/pulls\/7\/reviews\/101$/.test(call.url)));
  assert.equal(task.publication_state, "publication_skipped_duplicate", String(task.publication_error || ""));
  assert.equal(task.publication_review_id, 101);
});

test("approves only a complete no-findings PR review", () => {
  const normalized = normalizeReviewPublication(reviewTask(), completeReview());
  assert.equal(normalized.evidenceComplete, true);
  assert.equal(normalized.decision, "APPROVE");
});

test("uses COMMENT for contradictory evidence and includes validation and GitHub file links", async () => {
  const task = reviewTask();
  const result = completeReview();
  const review = result.review as JsonObject;
  review.tests_run = [{command: "npm test", status: "passed", output_summary: "not run"}];
  result.summary = "npm test - not run";
  const normalized = normalizeReviewPublication(task, result);

  assert.equal(normalized.decision, "COMMENT");
  assert.equal(normalized.evidenceComplete, false);
  assert.match(normalized.validationIssues.join("\n"), /contradictory/);

  const stateDir = tempStateDir();
  const config = testConfig(stateDir);
  prepareReviewWorkspace(config, task);
  const resultPath = join(stateDir, "result.json");
  writeFileSync(resultPath, JSON.stringify(result));
  let published = "";
  await withGithubApiMock((url, init) => {
    const read = githubReadFixture(url, init);
    if (read) return read;
    published = String(init.body);
    return {id: 102, html_url: "https://github.com/OpenCoven/example/pull/7#pullrequestreview-102"};
  }, async () => publishResultIfConfigured(config, task, resultPath, "token"));

  assert.match(published, /"event":"COMMENT"/);
  assert.match(published, /Publication validation/);
  assert.match(published, /https:\/\/github\.com\/OpenCoven\/example\/blob\/abc123\/src\/app\.ts/);
});

test("a newer review links the prior covencat publication with conditional replacement wording", async () => {
  const stateDir = tempStateDir();
  const config = testConfig(stateDir);
  const resultPath = join(stateDir, "result.json");
  writeFileSync(resultPath, JSON.stringify(completeReview()));
  const bodies: string[] = [];
  const dismissals: JsonObject[] = [];
  let id = 200;
  let activeId = 0;
  const firstTask = reviewTask("first-run");
  const secondTask = reviewTask("newer-run");
  prepareReviewWorkspace(config, firstTask);
  prepareReviewWorkspace(config, secondTask);
  await withGithubApiMock((url, init) => {
    const read = githubReadFixture(url, init);
    if (read) return read;
    if (init.method === "PUT") {
      dismissals.push(JSON.parse(String(init.body)) as JsonObject);
      return {state: "DISMISSED"};
    }
    if (/\/pulls\/7\/reviews$/.test(url)) {
      bodies.push(String(init.body));
      id += 1;
      activeId = id;
      return {id: activeId, state: "PENDING", html_url: `https://github.com/OpenCoven/example/pull/7#pullrequestreview-${activeId}`};
    }
    const event = String((JSON.parse(String(init.body)) as JsonObject).event);
    return {id: activeId, state: event === "APPROVE" ? "APPROVED" : "CHANGES_REQUESTED", html_url: `https://github.com/OpenCoven/example/pull/7#pullrequestreview-${activeId}`};
  }, async () => {
    await publishResultIfConfigured(config, firstTask, resultPath, "token");
    await publishResultIfConfigured(config, secondTask, resultPath, "token");
  });

  assert.equal(bodies.length, 2);
  assert.match(bodies[1], /A decisive submission replaces its state; a COMMENT does not/);
  assert.match(bodies[1], /pullrequestreview-201/);
  assert.equal(dismissals[0].event, "DISMISS");
  assert.equal(secondTask.publication_supersession_state, "prior_decisive_review_dismissed");
});

test("keeps a finding in the review body when its line is not in the captured diff", async () => {
  const stateDir = tempStateDir();
  const config = testConfig(stateDir);
  const task = reviewTask("invalid-inline-location");
  prepareReviewWorkspace(config, task);
  const resultPath = join(stateDir, "result.json");
  writeFileSync(resultPath, JSON.stringify(completeReview([{severity: "high", file: "src/app.ts", line: 99, title: "Out-of-diff finding", body: "Outside the captured hunk.", recommendation: null}])));
  let published = "";
  await withGithubApiMock((url, init) => {
    const read = githubReadFixture(url, init);
    if (read) return read;
    published = String(init.body);
    return {id: 250, html_url: "https://github.com/OpenCoven/example/pull/7#pullrequestreview-250"};
  }, async () => publishResultIfConfigured(config, task, resultPath, "token"));
  const body = JSON.parse(published) as JsonObject;
  assert.equal(body.comments, undefined);
  assert.match(String(body.body), /Findings without valid inline locations/);
});

test("reports explicit overflow when a review has more findings than fit safely", async () => {
  const stateDir = tempStateDir();
  const config = testConfig(stateDir);
  const task = reviewTask("finding-overflow");
  prepareReviewWorkspace(config, task);
  const findings = Array.from({length: 41}, (_, index) => ({
    severity: "high",
    file: "src/app.ts",
    line: 99,
    title: `Finding ${index + 1}`,
    body: `Details for finding ${index + 1}.`,
    recommendation: null,
  }));
  const resultPath = join(stateDir, "result.json");
  writeFileSync(resultPath, JSON.stringify(completeReview(findings)));
  let reviewBody = "";
  await withGithubApiMock((url, init) => {
    const read = githubReadFixture(url, init);
    if (read) return read;
    const payload = JSON.parse(String(init.body)) as JsonObject;
    if (/\/pulls\/7\/reviews$/.test(url)) reviewBody = String(payload.body || "");
    return {id: 251, state: /\/events$/.test(url) ? "CHANGES_REQUESTED" : "PENDING", html_url: "https://github.com/OpenCoven/example/pull/7#pullrequestreview-251"};
  }, async () => publishResultIfConfigured(config, task, resultPath, "token"));
  assert.match(reviewBody, /Finding 40/);
  assert.match(reviewBody, /1 additional finding was omitted|1 additional findings were omitted/);
});

test("keeps non-PR task results as idempotent issue comments", async () => {
  const stateDir = tempStateDir();
  const task: JsonObject = {
    task_id: "issue-task",
    repository: "OpenCoven/example",
    publication: {mode: "comment"},
    task: {issue_number: 11},
  };
  const resultPath = join(stateDir, "result.json");
  writeFileSync(resultPath, JSON.stringify({status: "failure", summary: "Runtime was unavailable.", files_changed: [], commits: []}));
  const methods: string[] = [];
  let publishedBody = "";
  await withGithubApiMock((url, init) => {
    methods.push(String(init.method));
    if (init.method === "GET" && /\/issues\/comments\/301$/.test(url)) {
      return {id: 301, body: publishedBody, user: covencatBot(), html_url: "https://github.com/OpenCoven/example/issues/11#issuecomment-301"};
    }
    if (init.method === "GET") return [];
    publishedBody = String((JSON.parse(String(init.body)) as JsonObject).body || "");
    return {id: 301, html_url: "https://github.com/OpenCoven/example/issues/11#issuecomment-301"};
  }, async () => {
    await publishResultIfConfigured(testConfig(stateDir), task, resultPath, "token");
    await publishResultIfConfigured(testConfig(stateDir), task, resultPath, "token");
  });
  assert.deepEqual(methods, ["GET", "POST", "GET"]);
  assert.equal(task.publication_state, "publication_skipped_duplicate");
  assert.equal(task.publication_comment_id, 301);
});

test("downgrades incomplete, contradictory, or malformed review evidence", () => {
  const cases: Array<[string, (task: JsonObject, result: JsonObject) => void]> = [
    ["partial changed-file coverage", (_task, result) => { ((result.review as JsonObject).reviewed_files as JsonObject[]).pop(); }],
    ["dirty post-run workspace", (task) => { (task.review_evidence as JsonObject).publication_workspace_clean = false; }],
    ["stale remote head", (_task, _result) => {}],
    ["runtime failure", (_task, result) => { result.status = "failure"; }],
    ["review limitation", (_task, result) => { (result.review as JsonObject).limitations = ["Tests were unavailable."]; }],
    ["missing no-findings reason", (_task, result) => { (result.review as JsonObject).no_findings_reason = null; }],
    ["failed test", (_task, result) => { (result.review as JsonObject).tests_run = [{command: "npm test", status: "failed", output_summary: "1 failed"}]; }],
    ["missing test evidence", (_task, result) => { (result.review as JsonObject).tests_run = []; }],
    ["malformed finding", (_task, result) => { (result.review as JsonObject).findings = [{title: "missing required fields"}]; (result.review as JsonObject).no_findings_reason = null; }],
    ["findings with no-findings reason", (_task, result) => { (result.review as JsonObject).findings = [{severity: "high", file: "src/app.ts", line: 12, title: "Finding", body: "Body", recommendation: null}]; }],
    ["invalid supporting path", (_task, result) => { (result.review as JsonObject).supporting_files = ["435:  .map((entry) => entry)"]; }],
    ["truncated patch evidence", (task) => { (task.review_evidence as JsonObject).incomplete_patch_files = ["src/app.ts"]; }],
    ["wrong changed-file count", (task) => { (task.review_evidence as JsonObject).expected_changed_file_count = 3; }],
    ["missing host validation receipt", (task) => { delete (task.review_evidence as JsonObject).host_validation_checks; }],
    ["failed host validation receipt", (task) => { (((task.review_evidence as JsonObject).host_validation_checks as JsonObject[])[0]).returncode = 1; }],
    ["unmatched host validation command", (task) => { (((task.review_evidence as JsonObject).host_validation_checks as JsonObject[])[0]).command = "npm run build"; }],
    ["wrong contract", (_task, result) => { result.contract_version = "1"; }],
  ];

  for (const [name, mutate] of cases) {
    const task = reviewTask(`case-${name}`);
    const result = completeReview();
    mutate(task, result);
    const currentHead = name === "stale remote head" ? "new-head" : "abc123";
    const normalized = normalizeReviewPublication(task, result, currentHead);
    assert.equal(normalized.decision, "COMMENT", name);
    assert.equal(normalized.evidenceComplete, false, name);
  }
});

test("normalizes contradictory tests instead of publishing passed and not-run claims", async () => {
  const stateDir = tempStateDir();
  const config = testConfig(stateDir);
  const task = reviewTask("normalized-contradiction");
  prepareReviewWorkspace(config, task);
  const result = completeReview();
  result.summary = "Tests were not executed.";
  (result.review as JsonObject).tests_run = [{command: "npm test", status: "passed", output_summary: "all tests passed"}];
  const resultPath = join(stateDir, "result.json");
  writeFileSync(resultPath, JSON.stringify(result));
  let payload: JsonObject = {};
  await withGithubApiMock((url, init) => {
    const read = githubReadFixture(url, init);
    if (read) return read;
    payload = JSON.parse(String(init.body)) as JsonObject;
    return {id: 401, html_url: "https://github.com/OpenCoven/example/pull/7#pullrequestreview-401"};
  }, async () => publishResultIfConfigured(config, task, resultPath, "token"));
  assert.equal(payload.event, "COMMENT");
  assert.match(String(payload.body), /`unverified`/);
  assert.doesNotMatch(String(payload.body), /Tests were not executed/);
});

test("downgrades passed test claims with failure or missing-execution evidence", () => {
  const cases: Array<[string, (result: JsonObject) => void]> = [
    ["failed output", (result) => {
      (result.review as JsonObject).tests_run = [{command: "npm test", status: "passed", output_summary: "47 passed, 1 failed"}];
    }],
    ["failed narrative", (result) => {
      result.summary = "npm test failed with one failing test.";
    }],
    ["failing count", (result) => {
      (result.review as JsonObject).tests_run = [{command: "npm test", status: "passed", output_summary: "47 passing, 1 failing"}];
    }],
    ["did not pass", (result) => {
      (result.review as JsonObject).tests_run = [{command: "npm test", status: "passed", output_summary: "1 test did not pass"}];
    }],
    ["unsuccessful exit", (result) => {
      (result.review as JsonObject).tests_run = [{command: "npm test", status: "passed", output_summary: "npm test exited unsuccessfully"}];
    }],
    ["non-zero return", (result) => {
      (result.review as JsonObject).tests_run = [{command: "npm test", status: "passed", output_summary: "process returned non-zero"}];
    }],
    ["non-zero exit status", (result) => {
      (result.review as JsonObject).tests_run = [{command: "npm test", status: "passed", output_summary: "exit status 1"}];
    }],
    ["no tests narrative", (result) => {
      result.summary = "No tests were run.";
    }],
    ["skipped testing narrative", (result) => {
      result.summary = "Testing was skipped.";
    }],
    ["could not run narrative", (result) => {
      result.summary = "Tests could not be run.";
    }],
    ["zero tests output", (result) => {
      (result.review as JsonObject).tests_run = [{command: "npm test", status: "passed", output_summary: "Command exited 0; 0 tests were run."}];
    }],
    ["suite not executed output", (result) => {
      (result.review as JsonObject).tests_run = [{command: "npm test", status: "passed", output_summary: "The test suite was not executed."}];
    }],
  ];

  for (const [name, mutate] of cases) {
    const result = completeReview();
    mutate(result);
    const normalized = normalizeReviewPublication(reviewTask(`failed-test-${name}`), result, "abc123");
    assert.equal(normalized.decision, "COMMENT", name);
    assert.equal(normalized.evidenceComplete, false, name);
    assert.match(normalized.validationIssues.join("\n"), /contradictory or incomplete/, name);
    assert.equal((normalized.review.tests_run as JsonObject[])[0].status, "unverified", name);
  }
});

test("keeps explicitly successful test evidence decisive", () => {
  const cases: Array<[string, (result: JsonObject) => void]> = [
    ["zero failures", (result) => {
      (result.review as JsonObject).tests_run = [{command: "npm test", status: "passed", output_summary: "47 tests passed with 0 failures."}];
    }],
    ["none failed or skipped", (result) => {
      result.summary = "No tests failed and no tests were skipped.";
    }],
    ["none skipped", (result) => {
      result.summary = "All tests ran; none were skipped.";
    }],
  ];

  for (const [name, mutate] of cases) {
    const result = completeReview();
    mutate(result);
    const normalized = normalizeReviewPublication(reviewTask(`successful-test-${name}`), result, "abc123");
    assert.equal(normalized.decision, "APPROVE", name);
    assert.equal(normalized.evidenceComplete, true, name);
  }
});

test("infers LEFT for a deletion finding from captured diff lines", () => {
  const result = completeReview([{
    severity: "high",
    file: "src/app.ts",
    line: 9,
    title: "Deleted guard",
    body: "The guard was removed.",
    recommendation: "Restore the guard.",
  }]);
  const normalized = normalizeReviewPublication(reviewTask(), result, "abc123");
  assert.equal(normalized.decision, "REQUEST_CHANGES");
  assert.equal(normalized.inlineComments[0].side, "LEFT");
  assert.equal(normalized.inlineComments[0].line, 9);
});

test("accepts a deletion finding when the changed file is absent from the checked-out tree", () => {
  const root = tempStateDir();
  writeFileSync(join(root, "README.md"), "supporting evidence\n");
  const task = reviewTask("deleted-file");
  task.review_evidence = {
    head_sha: "abc123",
    base_sha: "base123",
    workspace_head_sha: "abc123",
    publication_workspace_head_sha: "abc123",
    publication_workspace_clean: true,
    changed_file_count: 1,
    expected_changed_file_count: 1,
    incomplete_patch_files: [],
    host_validation_checks: [{
      command: "npm test",
      returncode: 0,
      stdout_sha256: "a".repeat(64),
      stderr_sha256: "b".repeat(64),
    }],
    changed_files: ["src/deleted.ts"],
    changed_file_lines: [{path: "src/deleted.ts", left_lines: [9], right_lines: []}],
  };
  const result = completeReview([{
    severity: "high",
    file: "src/deleted.ts",
    line: 9,
    title: "Required guard was deleted",
    body: "Deleting this file removes the guard.",
    recommendation: "Restore the guard.",
  }]);
  (result.review as JsonObject).reviewed_files = ["src/deleted.ts"];
  const normalized = normalizeReviewPublication(task, result, "abc123", root);
  assert.equal(normalized.decision, "REQUEST_CHANGES");
  assert.equal(normalized.evidenceComplete, true);
  assert.equal(normalized.inlineComments[0].side, "LEFT");
});

test("rejects findings outside the captured changed-file set", () => {
  const result = completeReview([{
    severity: "high",
    file: "src/not-in-pr.ts",
    line: null,
    title: "Phantom finding",
    body: "This path was not part of the reviewed diff.",
    recommendation: null,
  }]);
  const normalized = normalizeReviewPublication(reviewTask(), result, "abc123");
  assert.equal(normalized.decision, "COMMENT");
  assert.match(normalized.validationIssues.join("\n"), /outside the verified changed-file set/);
});

test("detects a patch already truncated by the GitHub files API", () => {
  const completePatch = "@@ -1,2 +1,2 @@\n-old one\n-old two\n+new one\n+new two";
  assert.equal(patchEvidenceIncomplete(completePatch, 2, 2), false);
  assert.equal(patchEvidenceIncomplete(completePatch.slice(0, -9), 2, 2), true);
});

test("rejects syntactically valid supporting paths that are missing from the checkout", () => {
  const root = tempStateDir();
  const task = reviewTask();
  const result = completeReview();
  (result.review as JsonObject).supporting_files = ["docs/does-not-exist.md"];
  const normalized = normalizeReviewPublication(task, result, "abc123", root);
  assert.equal(normalized.decision, "COMMENT");
  assert.match(normalized.validationIssues.join("\n"), /missing repository path/);
});

test("rejects supporting paths that traverse a checkout symlink", () => {
  const root = tempStateDir();
  const outside = join(tempStateDir(), "outside.md");
  writeFileSync(outside, "outside evidence\n");
  symlinkSync(outside, join(root, "linked.md"));
  const task = reviewTask();
  const result = completeReview();
  (result.review as JsonObject).supporting_files = ["linked.md"];
  const normalized = normalizeReviewPublication(task, result, "abc123", root);
  assert.equal(normalized.decision, "COMMENT");
  assert.match(normalized.validationIssues.join("\n"), /missing repository path/);
});

test("paginates GitHub list endpoints until the final partial page", async () => {
  const urls: string[] = [];
  await withGithubApiMock((url) => {
    urls.push(url);
    return /[?&]page=1(?:&|$)/.test(url) ? Array.from({length: 100}, (_, id) => ({id})) : [{id: 100}];
  }, async () => {
    const items = await githubRequestAllPages("https://api.github.com/repos/OpenCoven/example/pulls/7/files", "token");
    assert.equal(items.length, 101);
  });
  assert.match(urls[0], /page=1/);
  assert.match(urls[1], /page=2/);
});

test("does not retry a review on unrelated GitHub API failures", async () => {
  for (const [status, response] of [
    [500, {message: "internal error"}],
    [422, {message: "Validation failed, or the endpoint has been spammed."}],
  ] as Array<[number, JsonObject]>) {
    const stateDir = tempStateDir();
    const config = testConfig(stateDir);
    const task = reviewTask(`api-${status}`);
    prepareReviewWorkspace(config, task);
    const resultPath = join(stateDir, "result.json");
    writeFileSync(resultPath, JSON.stringify(completeReview()));
    let posts = 0;
    await withGithubApiMock((url, init) => {
      const read = githubReadFixture(url, init);
      if (read) return read;
      posts += 1;
      return {httpStatus: status, response};
    }, async () => publishResultIfConfigured(config, task, resultPath, "token"));
    assert.equal(posts, 1);
    assert.equal(task.publication_state, "publication_failed");
  }
});

test("retries without inline comments only for a deterministic diff-location 422", async () => {
  const stateDir = tempStateDir();
  const config = testConfig(stateDir);
  const task = reviewTask("inline-422");
  prepareReviewWorkspace(config, task);
  const resultPath = join(stateDir, "result.json");
  writeFileSync(resultPath, JSON.stringify(completeReview([{
    severity: "high", file: "src/app.ts", line: 12, title: "Finding", body: "Body", recommendation: null,
  }])));
  const posts: JsonObject[] = [];
  await withGithubApiMock((url, init) => {
    const read = githubReadFixture(url, init);
    if (read) return read;
    const payload = JSON.parse(String(init.body)) as JsonObject;
    posts.push(payload);
    if (posts.length === 1) return {httpStatus: 422, response: {message: "review comment line must be part of the diff"}};
    return {
      id: 402,
      state: /\/events$/.test(url) ? "CHANGES_REQUESTED" : "PENDING",
      html_url: "https://github.com/OpenCoven/example/pull/7#pullrequestreview-402",
    };
  }, async () => publishResultIfConfigured(config, task, resultPath, "token"));
  assert.equal(posts.length, 3);
  assert.equal((posts[0].comments as JsonObject[]).length, 1);
  assert.equal(posts[1].comments, undefined);
  assert.equal(posts[2].event, "REQUEST_CHANGES");
  assert.equal(task.publication_state, "published_review");
});

test("near-limit inline fallback preserves a complete trusted marker and remains idempotent", async () => {
  const stateDir = tempStateDir();
  const config = testConfig(stateDir);
  const task = reviewTask("near-limit-inline-fallback");
  prepareReviewWorkspace(config, task);
  const result = completeReview([{
    severity: "high", file: "src/app.ts", line: 12, title: "Finding", body: "Body", recommendation: null,
  }]);
  result.summary = "x".repeat(59_500);
  const resultPath = join(stateDir, "near-limit-result.json");
  writeFileSync(resultPath, JSON.stringify(result));
  let publishedBody = "";
  let reviewState = "";
  let reviewPosts = 0;
  let submissions = 0;
  await withGithubApiMock((url, init) => {
    if (/\/pulls\/7$/.test(url)) return {head: {sha: "abc123"}, base: {sha: "base123"}};
    if (init.method === "GET" && /\/pulls\/7\/reviews\/4021$/.test(url)) {
      return {id: 4021, state: reviewState, commit_id: "abc123", body: publishedBody, html_url: "https://github.com/OpenCoven/example/pull/7#pullrequestreview-4021", user: covencatBot()};
    }
    if (init.method === "GET" && /\/pulls\/7\/reviews(?:\?|$)/.test(url)) {
      return publishedBody ? [{
        id: 4021,
        state: reviewState,
        commit_id: "abc123",
        body: publishedBody,
        html_url: "https://github.com/OpenCoven/example/pull/7#pullrequestreview-4021",
        user: covencatBot(),
      }] : [];
    }
    if (init.method === "GET") return [];
    if (init.method === "POST" && /\/pulls\/7\/reviews$/.test(url)) {
      reviewPosts += 1;
      const payload = JSON.parse(String(init.body)) as JsonObject;
      if (payload.comments) return {httpStatus: 422, response: {message: "review comment line must be part of the diff"}};
      publishedBody = String(payload.body || "");
      reviewState = "PENDING";
      return {id: 4021, state: reviewState, html_url: "https://github.com/OpenCoven/example/pull/7#pullrequestreview-4021"};
    }
    if (init.method === "POST" && /\/events$/.test(url)) {
      submissions += 1;
      reviewState = "CHANGES_REQUESTED";
      return {id: 4021, state: reviewState, html_url: "https://github.com/OpenCoven/example/pull/7#pullrequestreview-4021"};
    }
    return {id: 4021};
  }, async () => {
    await publishResultIfConfigured(config, task, resultPath, "token");
    await publishResultIfConfigured(config, task, resultPath, "token");
  });
  assert.equal(reviewPosts, 2);
  assert.equal(submissions, 1);
  assert.ok(publishedBody.length <= 60_000);
  assert.match(publishedBody, /Inline publication was unavailable/);
  assert.match(publishedBody, /<!-- covencat-publication:[a-f0-9]{64} -->\n<!-- covencat-review-base:base123 -->\n<!-- covencat-publication-proof:[a-f0-9]{64} -->$/);
  assert.equal(task.publication_state, "publication_skipped_duplicate", String(task.publication_error || ""));
});

test("downgrades a forbidden decisive self-review to COMMENT", async () => {
  const stateDir = tempStateDir();
  const config = testConfig(stateDir);
  const task = reviewTask("self-review");
  prepareReviewWorkspace(config, task);
  const resultPath = join(stateDir, "result.json");
  writeFileSync(resultPath, JSON.stringify(completeReview([{
    severity: "high", file: "src/app.ts", line: 12, title: "Finding", body: "Body", recommendation: null,
  }])));
  const events: string[] = [];
  await withGithubApiMock((url, init) => {
    const read = githubReadFixture(url, init);
    if (read) return read;
    const payload = JSON.parse(String(init.body)) as JsonObject;
    if (/\/pulls\/7\/reviews$/.test(url)) {
      assert.equal(payload.event, undefined);
      assert.equal((payload.comments as JsonObject[]).length, 1);
      return {id: 403, state: "PENDING", html_url: "https://github.com/OpenCoven/example/pull/7#pullrequestreview-403"};
    }
    events.push(String(payload.event));
    if (events.length === 1) return {httpStatus: 422, response: {message: "Can not approve your own pull request"}};
    return {id: 403, state: "COMMENTED", html_url: "https://github.com/OpenCoven/example/pull/7#pullrequestreview-403"};
  }, async () => publishResultIfConfigured(config, task, resultPath, "token"));
  assert.deepEqual(events, ["REQUEST_CHANGES", "COMMENT"]);
  assert.equal(task.publication_decision, "COMMENT");
});

test("publishes a successful PR result without review evidence as native COMMENT", async () => {
  const stateDir = tempStateDir();
  const config = testConfig(stateDir);
  const task = reviewTask("missing-review");
  prepareReviewWorkspace(config, task);
  const result = completeReview();
  delete result.review;
  const resultPath = join(stateDir, "result.json");
  writeFileSync(resultPath, JSON.stringify(result));
  let event = "";
  await withGithubApiMock((url, init) => {
    const read = githubReadFixture(url, init);
    if (read) return read;
    event = String((JSON.parse(String(init.body)) as JsonObject).event);
    return {id: 404, html_url: "https://github.com/OpenCoven/example/pull/7#pullrequestreview-404"};
  }, async () => publishResultIfConfigured(config, task, resultPath, "token"));
  assert.equal(event, "COMMENT");
});

test("publishes a partial PR result without review evidence as native COMMENT", async () => {
  const stateDir = tempStateDir();
  const config = testConfig(stateDir);
  const task = reviewTask("partial-missing-review");
  prepareReviewWorkspace(config, task);
  const result = completeReview();
  result.status = "partial";
  delete result.review;
  const resultPath = join(stateDir, "result.json");
  writeFileSync(resultPath, JSON.stringify(result));
  let event = "";
  await withGithubApiMock((url, init) => {
    const read = githubReadFixture(url, init);
    if (read) return read;
    event = String((JSON.parse(String(init.body)) as JsonObject).event);
    return {id: 4041, html_url: "https://github.com/OpenCoven/example/pull/7#pullrequestreview-4041"};
  }, async () => publishResultIfConfigured(config, task, resultPath, "token"));
  assert.equal(event, "COMMENT");
});

test("resumes a persisted pending publication without rerunning the completed task", async () => {
  const stateDir = tempStateDir();
  const config = testConfig(stateDir);
  const task = reviewTask("resume-pending-publication");
  const resultPath = join(stateDir, "resume-result.json");
  Object.assign(task, {
    state: "completed",
    attempts: 4,
    runtime_exit_code: 0,
    result_path: resultPath,
    publication_state: "publication_pending",
    installation_id: 12345,
    repository_id: 98765,
  });
  prepareReviewWorkspace(config, task);
  writeFileSync(resultPath, JSON.stringify(completeReview()));
  writeFileSync(join(config.tasksDir, `${task.task_id}.json`), JSON.stringify(task));

  let providedConfig: typeof config | undefined;
  let providedTask: JsonObject | undefined;
  let reviewCreates = 0;
  let submissions = 0;
  const tokenProvider = async (candidateConfig: typeof config, candidateTask: JsonObject): Promise<string> => {
    providedConfig = candidateConfig;
    providedTask = candidateTask;
    return "task-aware-token";
  };

  await withGithubApiMock((url, init) => {
    const read = githubReadFixture(url, init);
    if (read) return read;
    if (/\/pulls\/7\/reviews$/.test(url)) {
      reviewCreates += 1;
      return {id: 650, state: "PENDING", html_url: "https://github.com/OpenCoven/example/pull/7#pullrequestreview-650"};
    }
    if (/\/events$/.test(url)) {
      submissions += 1;
      return {id: 650, state: "APPROVED", html_url: "https://github.com/OpenCoven/example/pull/7#pullrequestreview-650"};
    }
    return {id: 650};
  }, async () => resumeTaskPublication(config, String(task.task_id), () => {}, tokenProvider));

  const persisted = JSON.parse(readFileSync(join(config.tasksDir, `${task.task_id}.json`), "utf8")) as JsonObject;
  assert.equal(providedConfig, config);
  assert.equal(providedTask?.task_id, task.task_id);
  assert.equal(providedTask?.installation_id, 12345);
  assert.equal(providedTask?.repository_id, 98765);
  assert.equal(reviewCreates, 1);
  assert.equal(submissions, 1);
  assert.equal(persisted.state, "completed");
  assert.equal(persisted.attempts, 4);
  assert.equal(persisted.runtime_exit_code, 0);
  assert.equal(persisted.publication_attempts, 1);
  assert.equal(persisted.publication_state, "published_review");
  assert.equal(persisted.publication_review_id, 650);
});

test("blocks recovery when a finalized task has no result artifact", async () => {
  const stateDir = tempStateDir();
  const config = testConfig(stateDir);
  const task = reviewTask("resume-missing-result");
  Object.assign(task, {
    state: "completed",
    result_path: join(stateDir, "missing-result.json"),
    publication_state: "publication_pending",
    installation_id: 12345,
  });
  writeFileSync(join(config.tasksDir, `${task.task_id}.json`), JSON.stringify(task));
  let tokenCalls = 0;

  await resumeTaskPublication(config, String(task.task_id), () => {}, async (_candidateConfig, _candidateTask) => {
    tokenCalls += 1;
    return "unused-token";
  });

  const persisted = JSON.parse(readFileSync(join(config.tasksDir, `${task.task_id}.json`), "utf8")) as JsonObject;
  assert.equal(tokenCalls, 0);
  assert.equal(persisted.state, "completed");
  assert.equal(persisted.publication_state, "publication_blocked_missing_result");
  assert.match(String(persisted.publication_error), /no readable result artifact/);
});

test("duplicate delivery queues publication recovery without blocking the webhook", async () => {
  const secret = "duplicate-recovery-secret";
  const stateDir = tempStateDir();
  const config = testConfig(stateDir, secret);
  const task = reviewTask("duplicate-blocked-recovery");
  Object.assign(task, {
    state: "completed",
    result_path: join(stateDir, "missing-duplicate-result.json"),
    publication_state: "publication_pending",
    installation_id: 12345,
  });
  writeFileSync(join(config.tasksDir, `${task.task_id}.json`), JSON.stringify(task));
  writeFileSync(join(config.deliveriesDir, `${task.task_id}.json`), JSON.stringify({
    delivery_id: task.task_id,
    task_id: task.task_id,
    state: "completed",
    publication_state: "publication_pending",
  }));
  const body = Buffer.from("{}");
  const response = await callWebhook(body, {
    "X-GitHub-Event": "ping",
    "X-GitHub-Delivery": String(task.task_id),
    "X-Hub-Signature-256": signature(secret, body),
  }, "auto", config);
  assert.equal(response.body.action, "duplicate_retry_queued");
  assert.equal(response.body.queued, true);
  assert.equal(response.body.publication_state, "publication_pending");
  const recovered = await runTask(config, String(task.task_id));
  assert.equal(recovered.publication_state, "publication_blocked_missing_result");
});

test("startup publication recovery skips corrupt task records and continues", async () => {
  const stateDir = tempStateDir();
  const config = testConfig(stateDir);
  writeFileSync(join(config.tasksDir, "corrupt-task.json"), "{not-json");
  const task = reviewTask("recover-after-corrupt-task");
  Object.assign(task, {
    state: "completed",
    result_path: join(stateDir, "missing-startup-result.json"),
    publication_state: "publication_pending",
    installation_id: 12345,
  });
  writeFileSync(join(config.tasksDir, `${task.task_id}.json`), JSON.stringify(task));
  const debugMessages: string[] = [];
  let tokenCalls = 0;
  const attempted = await recoverPendingPublications(config, (message) => debugMessages.push(message), async () => {
    tokenCalls += 1;
    return "unused-token";
  });
  assert.equal(attempted, 1);
  assert.equal(tokenCalls, 0);
  assert.ok(debugMessages.some((message) => /corrupt-task.*unreadable task/.test(message)));
  const persisted = JSON.parse(readFileSync(join(config.tasksDir, `${task.task_id}.json`), "utf8")) as JsonObject;
  assert.equal(persisted.publication_state, "publication_blocked_missing_result");
});

test("blocks publication recovery for legacy tasks without an isolation receipt", async () => {
  const stateDir = tempStateDir();
  const config = testConfig(stateDir);
  const task = reviewTask("resume-unverified-runtime");
  delete task.runtime_isolation;
  const resultPath = join(stateDir, "legacy-result.json");
  Object.assign(task, {
    state: "completed",
    result_path: resultPath,
    publication_state: "publication_pending",
    installation_id: 12345,
  });
  writeFileSync(resultPath, JSON.stringify(completeReview()));
  writeFileSync(join(config.tasksDir, `${task.task_id}.json`), JSON.stringify(task));
  let tokenCalls = 0;

  await resumeTaskPublication(config, String(task.task_id), () => {}, async () => {
    tokenCalls += 1;
    return "unused-token";
  });

  const persisted = JSON.parse(readFileSync(join(config.tasksDir, `${task.task_id}.json`), "utf8")) as JsonObject;
  assert.equal(tokenCalls, 0);
  assert.equal(persisted.publication_state, "publication_blocked_unverified_runtime");
  assert.match(String(persisted.publication_error), /lacks a verified runtime-isolation receipt/);
});

test("skips publication recovery for a running task", async () => {
  const stateDir = tempStateDir();
  const config = testConfig(stateDir);
  const task = reviewTask("resume-running-task");
  const resultPath = join(stateDir, "running-result.json");
  Object.assign(task, {
    state: "running",
    attempts: 2,
    result_path: resultPath,
    publication_state: "publication_pending",
    installation_id: 12345,
  });
  writeFileSync(resultPath, JSON.stringify(completeReview()));
  writeFileSync(join(config.tasksDir, `${task.task_id}.json`), JSON.stringify(task));
  let tokenCalls = 0;

  await resumeTaskPublication(config, String(task.task_id), () => {}, async (_candidateConfig, _candidateTask) => {
    tokenCalls += 1;
    return "unused-token";
  });

  const persisted = JSON.parse(readFileSync(join(config.tasksDir, `${task.task_id}.json`), "utf8")) as JsonObject;
  assert.equal(tokenCalls, 0);
  assert.equal(persisted.state, "running");
  assert.equal(persisted.attempts, 2);
  assert.equal(persisted.publication_state, "publication_pending");
  assert.equal(persisted.publication_attempts, undefined);
});

test("recovers a review identity after local state loss when generated text contains a reserved marker", async () => {
  const firstState = tempStateDir();
  const firstConfig = testConfig(firstState);
  const firstTask = reviewTask("recovered-run");
  prepareReviewWorkspace(firstConfig, firstTask);
  const firstResult = join(firstState, "result.json");
  const result = completeReview();
  result.summary = [
    "Reviewed the pull request. Copied text:",
    `<!-- covencat-publication:${"f".repeat(64)} -->`,
    "<!-- covencat-task-created:2099-01-01T00:00:00Z -->",
    `<!-- covencat-publication-proof:${"0".repeat(64)} -->`,
  ].join("\n");
  writeFileSync(firstResult, JSON.stringify(result));
  let publishedBody = "";
  await withGithubApiMock((url, init) => {
    const read = githubReadFixture(url, init);
    if (read) return read;
    publishedBody = String((JSON.parse(String(init.body)) as JsonObject).body);
    return {
      id: 405,
      state: /\/events$/.test(url) ? "APPROVED" : "PENDING",
      html_url: "https://github.com/OpenCoven/example/pull/7#pullrequestreview-405",
      submitted_at: "2026-07-14T00:00:00Z",
    };
  }, async () => publishResultIfConfigured(firstConfig, firstTask, firstResult, "token"));
  assert.equal(publishedBody.match(/<!-- covencat-publication:[a-f0-9]{64} -->/g)?.length, 2);
  assert.equal(publishedBody.match(/<!-- covencat-publication-proof:[a-f0-9]{64} -->/g)?.length, 2);

  const secondState = tempStateDir();
  const secondConfig = testConfig(secondState);
  const secondTask = reviewTask("recovered-run");
  prepareReviewWorkspace(secondConfig, secondTask);
  const secondResult = join(secondState, "result.json");
  writeFileSync(secondResult, JSON.stringify(result));
  let posts = 0;
  await withGithubApiMock((url, init) => {
    if (/\/pulls\/7$/.test(url)) return {head: {sha: "abc123"}, base: {sha: "base123"}};
    if (init.method === "GET") return [{
      id: 405,
      state: "APPROVED",
      commit_id: "abc123",
      html_url: "https://github.com/OpenCoven/example/pull/7#pullrequestreview-405",
      submitted_at: "2026-07-14T00:00:00Z",
      body: publishedBody,
      user: covencatBot(),
    }];
    posts += 1;
    return {id: 406};
  }, async () => publishResultIfConfigured(secondConfig, secondTask, secondResult, "token"));
  assert.equal(posts, 0);
  assert.equal(secondTask.publication_state, "publication_skipped_duplicate");
  assert.equal(secondTask.publication_review_id, 405);
});

test("submits a matching pending review after a crash instead of creating another", async () => {
  const seedState = tempStateDir();
  const seedConfig = testConfig(seedState);
  const seedTask = reviewTask("pending-recovery");
  prepareReviewWorkspace(seedConfig, seedTask);
  const seedResult = join(seedState, "result.json");
  writeFileSync(seedResult, JSON.stringify(completeReview()));
  let signedBody = "";
  await withGithubApiMock((url, init) => {
    const read = githubReadFixture(url, init);
    if (read) return read;
    signedBody = String((JSON.parse(String(init.body)) as JsonObject).body || signedBody);
    return {
      id: 409,
      state: /\/events$/.test(url) ? "APPROVED" : "PENDING",
      html_url: "https://github.com/OpenCoven/example/pull/7#pullrequestreview-409",
    };
  }, async () => publishResultIfConfigured(seedConfig, seedTask, seedResult, "token"));

  const retryState = tempStateDir();
  const retryConfig = testConfig(retryState);
  const retryTask = reviewTask("pending-recovery");
  prepareReviewWorkspace(retryConfig, retryTask);
  const retryResult = join(retryState, "result.json");
  writeFileSync(retryResult, JSON.stringify(completeReview()));
  let creates = 0;
  let submissions = 0;
  await withGithubApiMock((url, init) => {
    if (/\/pulls\/7$/.test(url)) return {head: {sha: "abc123"}, base: {sha: "base123"}};
    if (init.method === "GET") return [{
      id: 409,
      state: "PENDING",
      commit_id: "abc123",
      body: signedBody,
      html_url: "https://github.com/OpenCoven/example/pull/7#pullrequestreview-409",
      user: covencatBot(),
    }];
    if (/\/pulls\/7\/reviews$/.test(url)) creates += 1;
    if (/\/events$/.test(url)) submissions += 1;
    return {id: 409, state: "APPROVED", html_url: "https://github.com/OpenCoven/example/pull/7#pullrequestreview-409"};
  }, async () => publishResultIfConfigured(retryConfig, retryTask, retryResult, "token"));
  assert.equal(creates, 0);
  assert.equal(submissions, 1);
  assert.equal(retryTask.publication_state, "published_review_recovered");
});

test("retries a failed decisive-review dismissal without republishing the new review", async () => {
  const stateDir = tempStateDir();
  const config = testConfig(stateDir);
  const resultPath = join(stateDir, "result.json");
  writeFileSync(resultPath, JSON.stringify(completeReview()));
  const firstTask = reviewTask("supersession-first");
  const secondTask = reviewTask("supersession-second");
  const retryTask = reviewTask("supersession-second");
  prepareReviewWorkspace(config, firstTask);
  prepareReviewWorkspace(config, secondTask);
  let nextReviewId = 500;
  let activeReviewId = 0;
  let posts = 0;
  let dismissals = 0;
  const reviewBodies = new Map<number, string>();
  const reviewStates = new Map<number, string>();
  await withGithubApiMock((url, init) => {
    if (init.method === "GET" && /\/pulls\/7$/.test(url)) return {head: {sha: "abc123"}, base: {sha: "base123"}};
    const exactReviewId = Number(url.match(/\/pulls\/7\/reviews\/(\d+)$/)?.[1] || 0);
    if (init.method === "GET" && exactReviewId) {
      return {
        id: exactReviewId,
        state: reviewStates.get(exactReviewId) || "APPROVED",
        body: reviewBodies.get(exactReviewId) || "signed review body",
        html_url: `https://github.com/OpenCoven/example/pull/7#pullrequestreview-${exactReviewId}`,
        user: covencatBot(),
      };
    }
    if (init.method === "GET") return [];
    if (init.method === "POST" && /\/pulls\/7\/reviews$/.test(url)) {
      posts += 1;
      nextReviewId += 1;
      activeReviewId = nextReviewId;
      reviewBodies.set(activeReviewId, String((JSON.parse(String(init.body)) as JsonObject).body || ""));
      reviewStates.set(activeReviewId, "PENDING");
      return {id: activeReviewId, state: "PENDING", html_url: `https://github.com/OpenCoven/example/pull/7#pullrequestreview-${activeReviewId}`};
    }
    if (init.method === "POST") {
      reviewStates.set(activeReviewId, "APPROVED");
      return {id: activeReviewId, state: "APPROVED", html_url: `https://github.com/OpenCoven/example/pull/7#pullrequestreview-${activeReviewId}`};
    }
    if (/\/dismissals$/.test(url)) {
      dismissals += 1;
      if (dismissals === 1) return {httpStatus: 500, response: {message: "temporary failure"}};
      assert.equal((JSON.parse(String(init.body)) as JsonObject).event, "DISMISS");
      const dismissedId = Number(url.match(/\/reviews\/(\d+)\/dismissals$/)?.[1] || 0);
      reviewStates.set(dismissedId, "DISMISSED");
      return {state: "DISMISSED"};
    }
    if (init.method === "PUT" && exactReviewId) {
      reviewBodies.set(exactReviewId, String((JSON.parse(String(init.body)) as JsonObject).body || ""));
      return {id: exactReviewId, state: reviewStates.get(exactReviewId) || "APPROVED"};
    }
    return {id: nextReviewId};
  }, async () => {
    await publishResultIfConfigured(config, firstTask, resultPath, "token");
    await publishResultIfConfigured(config, secondTask, resultPath, "token");
    assert.equal(secondTask.publication_supersession_state, "prior_decisive_review_dismissal_failed");
    await publishResultIfConfigured(config, retryTask, resultPath, "token");
  });
  assert.equal(posts, 2);
  assert.equal(dismissals, 2);
  assert.equal(retryTask.publication_state, "publication_skipped_duplicate");
  assert.equal(retryTask.publication_supersession_state, "prior_decisive_review_dismissed");
});

test("does not let an older revision supersede a current-head GitHub review", async () => {
  const stateDir = tempStateDir();
  const config = testConfig(stateDir);
  const task = reviewTask("late-old-revision");
  const evidence = task.review_evidence as JsonObject;
  evidence.head_sha = "oldsha";
  evidence.workspace_head_sha = "oldsha";
  evidence.publication_workspace_head_sha = "oldsha";
  const resultPath = join(stateDir, "result.json");
  writeFileSync(resultPath, JSON.stringify(completeReview()));
  const writes: string[] = [];
  await withGithubApiMock((url, init) => {
    if (/\/pulls\/7$/.test(url)) return {head: {sha: "abc123"}, base: {sha: "base123"}};
    if (init.method === "GET") return [{
      id: 601,
      state: "APPROVED",
      commit_id: "abc123",
      submitted_at: "2026-07-14T12:00:00Z",
      body: `current review\n\n${signedPublicationMarker("b".repeat(64))}`,
      user: covencatBot(),
    }];
    writes.push(`${String(init.method)} ${url}`);
    return {id: 602};
  }, async () => publishResultIfConfigured(config, task, resultPath, "token"));
  assert.deepEqual(writes, []);
  assert.equal(task.publication_state, "publication_skipped_stale_revision");
});

test("does not let an older same-head run supersede a newer GitHub publication", async () => {
  const stateDir = tempStateDir();
  const config = testConfig(stateDir);
  const task = reviewTask("late-same-head-run");
  task.created_at = "2026-07-14T10:00:00Z";
  const resultPath = join(stateDir, "result.json");
  writeFileSync(resultPath, JSON.stringify(completeReview()));
  let writes = 0;
  await withGithubApiMock((url, init) => {
    if (/\/pulls\/7$/.test(url)) return {head: {sha: "abc123"}, base: {sha: "base123"}};
    if (init.method === "GET") return [{
      id: 603,
      state: "APPROVED",
      commit_id: "abc123",
      submitted_at: "2026-07-14T12:01:00Z",
      body: `newer review\n\n${signedPublicationMarker("c".repeat(64), "2026-07-14T11:00:00Z")}`,
      user: covencatBot(),
    }];
    writes += 1;
    return {id: 604};
  }, async () => publishResultIfConfigured(config, task, resultPath, "token"));
  assert.equal(writes, 0);
  assert.equal(task.publication_state, "publication_skipped_stale_run");
});

test("compares stale runs against the evidence head even after reviews on another head", async () => {
  const stateDir = tempStateDir();
  const config = testConfig(stateDir);
  const task = reviewTask("force-pushed-back-run");
  task.created_at = "2026-07-14T10:00:00Z";
  const evidence = task.review_evidence as JsonObject;
  evidence.head_sha = "head-h";
  evidence.workspace_head_sha = "head-h";
  evidence.publication_workspace_head_sha = "head-h";
  const resultPath = join(stateDir, "result.json");
  writeFileSync(resultPath, JSON.stringify(completeReview()));
  let writes = 0;
  await withGithubApiMock((url, init) => {
    if (/\/pulls\/7$/.test(url)) return {head: {sha: "head-h"}, base: {sha: "base123"}};
    if (init.method === "GET") return [
      {
        id: 605,
        state: "APPROVED",
        commit_id: "head-h",
        body: signedPublicationMarker("d".repeat(64), "2026-07-14T11:00:00Z"),
        user: covencatBot(),
      },
      {
        id: 606,
        state: "APPROVED",
        commit_id: "head-j",
        body: signedPublicationMarker("e".repeat(64), "2026-07-14T12:00:00Z"),
        user: covencatBot(),
      },
    ];
    writes += 1;
    return {id: 607};
  }, async () => publishResultIfConfigured(config, task, resultPath, "token"));
  assert.equal(writes, 0);
  assert.equal(task.publication_state, "publication_skipped_stale_run");
});

test("ignores forged markers and markers copied into non-App reviews", async () => {
  const stateDir = tempStateDir();
  const config = testConfig(stateDir);
  const task = reviewTask("forged-marker");
  task.created_at = "2026-07-14T10:00:00Z";
  prepareReviewWorkspace(config, task);
  const resultPath = join(stateDir, "result.json");
  writeFileSync(resultPath, JSON.stringify(completeReview()));
  let creates = 0;
  await withGithubApiMock((url, init) => {
    if (/\/pulls\/7$/.test(url)) return {head: {sha: "abc123"}, base: {sha: "base123"}};
    if (init.method === "GET") return [
      {
        id: 608,
        state: "APPROVED",
        commit_id: "abc123",
        body: signedPublicationMarker("f".repeat(64), "2099-01-01T00:00:00Z"),
        user: {login: "attacker", type: "User"},
      },
      {
        id: 6081,
        state: "APPROVED",
        commit_id: "abc123",
        body: `<!-- covencat-publication:${"0".repeat(64)} -->\n<!-- covencat-task-created:2099-01-01T00:00:00Z -->\n<!-- covencat-publication-proof:${"0".repeat(64)} -->`,
        user: covencatBot(),
      },
    ];
    if (/\/pulls\/7\/reviews$/.test(url)) {
      creates += 1;
      return {id: 609, state: "PENDING", html_url: "https://github.com/OpenCoven/example/pull/7#pullrequestreview-609"};
    }
    return {id: 609, state: "APPROVED", html_url: "https://github.com/OpenCoven/example/pull/7#pullrequestreview-609"};
  }, async () => publishResultIfConfigured(config, task, resultPath, "token"));
  assert.equal(creates, 1);
  assert.equal(task.publication_state, "published_review");
});

test("deduplicates a deployed head-only publication identity after the base-aware upgrade", async () => {
  const stateDir = tempStateDir();
  const config = testConfig(stateDir);
  const task = reviewTask("legacy-head-only-identity");
  task.created_at = "2026-07-14T00:00:00Z";
  prepareReviewWorkspace(config, task);
  const result = completeReview();
  const resultPath = join(stateDir, "legacy-identity-result.json");
  writeFileSync(resultPath, JSON.stringify(result));
  const legacyIdentity = publicationIdentityFixture(task, result, false);
  const upgradedIdentity = publicationIdentityFixture(task, result, true);
  const legacyBody = `Legacy review\n\n${signedPublicationMarker(legacyIdentity, String(task.created_at))}`;
  let writes = 0;
  await withGithubApiMock((url, init) => {
    if (/\/pulls\/7$/.test(url)) return {head: {sha: "abc123"}, base: {sha: "base123"}};
    if (init.method === "GET" && /\/pulls\/7\/reviews(?:\?|$)/.test(url)) return [{
      id: 6081,
      state: "APPROVED",
      commit_id: "abc123",
      body: legacyBody,
      submitted_at: "2026-07-14T00:01:00Z",
      html_url: "https://github.com/OpenCoven/example/pull/7#pullrequestreview-6081",
      user: covencatBot(),
    }];
    if (init.method === "GET") return [];
    writes += 1;
    return {id: 6081};
  }, async () => publishResultIfConfigured(config, task, resultPath, "token"));
  assert.notEqual(legacyIdentity, upgradedIdentity);
  assert.equal(writes, 0);
  assert.equal(task.publication_state, "publication_skipped_duplicate");
  assert.equal(task.publication_identity, upgradedIdentity);
  assert.equal(task.publication_review_id, 6081);
});

test("a stored legacy identity from another base is not deduplicated on the current base", async () => {
  const stateDir = tempStateDir();
  const config = testConfig(stateDir);
  const task = reviewTask("legacy-base-transition");
  task.created_at = "2026-07-14T00:05:00Z";
  prepareReviewWorkspace(config, task);
  const result = completeReview();
  const resultPath = join(stateDir, "legacy-base-transition-result.json");
  writeFileSync(resultPath, JSON.stringify(result));
  const legacyIdentity = publicationIdentityFixture(task, result, false);
  const legacyBody = `Legacy base-A review\n\n${signedPublicationMarker(legacyIdentity, "2026-07-14T00:00:00Z")}`;
  const recordName = `${createHash("sha256").update("OpenCoven/example#7").digest("hex").slice(0, 24)}.json`;
  writeFileSync(join(config.publicationsDir, recordName), JSON.stringify({
    identity: legacyIdentity,
    review_id: 6082,
    review_url: "https://github.com/OpenCoven/example/pull/7#pullrequestreview-6082",
    review_body: legacyBody,
    decision: "APPROVED",
    head_sha: "abc123",
    base_sha: "base-A",
  }));
  let creates = 0;
  let activeId = 6082;
  const dismissals: number[] = [];
  await withGithubApiMock((url, init) => {
    if (/\/pulls\/7$/.test(url)) return {head: {sha: "abc123"}, base: {sha: "base123"}};
    if (init.method === "GET" && /\/pulls\/7\/reviews(?:\?|$)/.test(url)) return [{
      id: 6082,
      state: "APPROVED",
      commit_id: "abc123",
      body: legacyBody,
      html_url: "https://github.com/OpenCoven/example/pull/7#pullrequestreview-6082",
      user: covencatBot(),
    }];
    if (init.method === "GET") return [];
    if (init.method === "POST" && /\/pulls\/7\/reviews$/.test(url)) {
      creates += 1;
      activeId = 6083;
      return {id: activeId, state: "PENDING", html_url: "https://github.com/OpenCoven/example/pull/7#pullrequestreview-6083"};
    }
    if (init.method === "POST" && /\/events$/.test(url)) {
      return {id: activeId, state: "APPROVED", html_url: "https://github.com/OpenCoven/example/pull/7#pullrequestreview-6083"};
    }
    if (init.method === "PUT" && /\/dismissals$/.test(url)) {
      dismissals.push(Number(url.match(/\/reviews\/(\d+)\/dismissals$/)?.[1] || 0));
      return {id: 6082, state: "DISMISSED"};
    }
    return {id: activeId};
  }, async () => publishResultIfConfigured(config, task, resultPath, "token"));
  assert.equal(creates, 1);
  assert.deepEqual(dismissals, [6082]);
  assert.equal(task.publication_state, "published_review");
  assert.equal(task.publication_review_id, 6083);
});

test("same-head reviews on different bases get distinct identities and current-base ordering", async () => {
  const stateDir = tempStateDir();
  const config = testConfig(stateDir);
  const result = completeReview();
  const resultPath = join(stateDir, "base-identity-result.json");
  writeFileSync(resultPath, JSON.stringify(result));
  const oldBaseTask = reviewTask("same-head-base-identity");
  const currentBaseTask = reviewTask("same-head-base-identity");
  oldBaseTask.created_at = "2026-07-14T00:00:00Z";
  currentBaseTask.created_at = "2026-07-14T00:05:00Z";
  (oldBaseTask.review_evidence as JsonObject).base_sha = "old-base";
  prepareReviewWorkspace(config, oldBaseTask);
  let currentBase = "old-base";
  let nextId = 6085;
  const reviews: JsonObject[] = [];
  const dismissed: number[] = [];
  await withGithubApiMock((url, init) => {
    if (/\/pulls\/7$/.test(url)) return {head: {sha: "abc123"}, base: {sha: currentBase}};
    if (init.method === "GET" && /\/pulls\/7\/reviews$/.test(url)) return reviews;
    if (init.method === "GET") return [];
    if (init.method === "POST" && /\/pulls\/7\/reviews$/.test(url)) {
      nextId += 1;
      const payload = JSON.parse(String(init.body)) as JsonObject;
      const review = {
        id: nextId,
        state: "PENDING",
        commit_id: "abc123",
        body: payload.body,
        html_url: `https://github.com/OpenCoven/example/pull/7#pullrequestreview-${nextId}`,
        user: covencatBot(),
      };
      reviews.push(review);
      return review;
    }
    if (init.method === "POST" && /\/events$/.test(url)) {
      const id = Number(url.match(/\/reviews\/(\d+)\/events$/)?.[1] || 0);
      const review = reviews.find((candidate) => candidate.id === id) as JsonObject;
      review.state = "APPROVED";
      review.submitted_at = currentBase === "old-base" ? "2026-07-14T00:01:00Z" : "2026-07-14T00:06:00Z";
      return review;
    }
    if (init.method === "PUT" && /\/dismissals$/.test(url)) {
      const id = Number(url.match(/\/reviews\/(\d+)\/dismissals$/)?.[1] || 0);
      dismissed.push(id);
      const review = reviews.find((candidate) => candidate.id === id) as JsonObject;
      review.state = "DISMISSED";
      return review;
    }
    return {id: nextId};
  }, async () => {
    await publishResultIfConfigured(config, oldBaseTask, resultPath, "token");
    currentBase = "base123";
    await publishResultIfConfigured(config, currentBaseTask, resultPath, "token");
  });
  assert.notEqual(oldBaseTask.publication_identity, currentBaseTask.publication_identity);
  assert.equal(reviews.length, 2);
  assert.match(String(reviews[0].body), /covencat-review-base:old-base/);
  assert.match(String(reviews[1].body), /covencat-review-base:base123/);
  assert.deepEqual(dismissed, [6086]);
  assert.equal(currentBaseTask.publication_state, "published_review");
  assert.equal(currentBaseTask.publication_review_id, 6087);
});

test("reconciles existing publications across signing-key rotation", async () => {
  const stateDir = tempStateDir();
  const oldConfig = createConfig({
    COVEN_GITHUB_STATE_DIR: stateDir,
    COVEN_GITHUB_POLICY_PATH: join(stateDir, "policy.json"),
    GITHUB_WEBHOOK_SECRET: "ingress-secret",
    COVEN_PUBLICATION_SIGNING_SECRET: "old-signing-secret",
  }, process.cwd());
  const firstTask = reviewTask("signing-key-rotation");
  prepareReviewWorkspace(oldConfig, firstTask);
  const resultPath = join(stateDir, "rotation-result.json");
  writeFileSync(resultPath, JSON.stringify(completeReview()));
  let oldBody = "";
  await withGithubApiMock((url, init) => {
    const read = githubReadFixture(url, init);
    if (read) return read;
    if (/\/pulls\/7\/reviews$/.test(url)) {
      oldBody = String((JSON.parse(String(init.body)) as JsonObject).body || "");
      return {id: 6091, state: "PENDING", html_url: "https://github.com/OpenCoven/example/pull/7#pullrequestreview-6091"};
    }
    if (/\/events$/.test(url)) return {id: 6091, state: "APPROVED", html_url: "https://github.com/OpenCoven/example/pull/7#pullrequestreview-6091"};
    return [];
  }, async () => publishResultIfConfigured(oldConfig, firstTask, resultPath, "token"));
  assert.match(oldBody, /covencat-publication-proof/);

  const rotatedConfig = createConfig({
    COVEN_GITHUB_STATE_DIR: stateDir,
    COVEN_GITHUB_POLICY_PATH: join(stateDir, "policy.json"),
    GITHUB_WEBHOOK_SECRET: "ingress-secret",
    COVEN_PUBLICATION_SIGNING_SECRET: "new-signing-secret",
    COVEN_PUBLICATION_PREVIOUS_SIGNING_SECRETS: "old-signing-secret",
  }, process.cwd());
  const retryTask = reviewTask("signing-key-rotation");
  prepareReviewWorkspace(rotatedConfig, retryTask);
  let writes = 0;
  let resignedBody = "";
  await withGithubApiMock((url, init) => {
    if (/\/pulls\/7$/.test(url)) return {head: {sha: "abc123"}, base: {sha: "base123"}};
    if (init.method === "GET" && /\/pulls\/7\/reviews/.test(url)) return [{
      id: 6091,
      state: "APPROVED",
      commit_id: "abc123",
      body: oldBody,
      user: covencatBot(),
    }];
    if (init.method === "GET") return [];
    writes += 1;
    resignedBody = String((JSON.parse(String(init.body)) as JsonObject).body || "");
    return {id: 6091, state: "APPROVED", body: resignedBody};
  }, async () => publishResultIfConfigured(rotatedConfig, retryTask, resultPath, "token"));
  assert.equal(writes, 1);
  assert.notEqual(resignedBody, oldBody);
  assert.match(resignedBody, /covencat-publication-proof/);
  assert.equal(retryTask.publication_state, "publication_skipped_duplicate");
  assert.equal(retryTask.publication_review_id, 6091);

  for (const entry of readdirSync(rotatedConfig.publicationsDir)) {
    rmSync(join(rotatedConfig.publicationsDir, entry), {recursive: true, force: true});
  }
  const newOnlyConfig = createConfig({
    COVEN_GITHUB_STATE_DIR: stateDir,
    COVEN_GITHUB_POLICY_PATH: join(stateDir, "policy.json"),
    GITHUB_WEBHOOK_SECRET: "ingress-secret",
    COVEN_PUBLICATION_SIGNING_SECRET: "new-signing-secret",
  }, process.cwd());
  const finalRetry = reviewTask("signing-key-rotation");
  prepareReviewWorkspace(newOnlyConfig, finalRetry);
  let finalWrites = 0;
  await withGithubApiMock((url, init) => {
    if (/\/pulls\/7$/.test(url)) return {head: {sha: "abc123"}, base: {sha: "base123"}};
    if (init.method === "GET" && /\/pulls\/7\/reviews/.test(url)) return [{
      id: 6091,
      state: "APPROVED",
      commit_id: "abc123",
      body: resignedBody,
      user: covencatBot(),
    }];
    if (init.method === "GET") return [];
    finalWrites += 1;
    return {id: 6091};
  }, async () => publishResultIfConfigured(newOnlyConfig, finalRetry, resultPath, "token"));
  assert.equal(finalWrites, 0);
  assert.equal(finalRetry.publication_state, "publication_skipped_duplicate");
  assert.equal(finalRetry.publication_review_id, 6091);
});

test("dismisses a decisive review when the head changes during submission", async () => {
  const stateDir = tempStateDir();
  const config = testConfig(stateDir);
  const task = reviewTask("head-race");
  prepareReviewWorkspace(config, task);
  const resultPath = join(stateDir, "result.json");
  writeFileSync(resultPath, JSON.stringify(completeReview()));
  let headReads = 0;
  const mutations: Array<{url: string; body: JsonObject}> = [];
  await withGithubApiMock((url, init) => {
    if (/\/pulls\/7$/.test(url)) {
      headReads += 1;
      return {head: {sha: headReads < 3 ? "abc123" : "new-head"}, base: {sha: "base123"}};
    }
    if (init.method === "GET") return [];
    const body = init.body ? JSON.parse(String(init.body)) as JsonObject : {};
    mutations.push({url, body});
    if (/\/pulls\/7\/reviews$/.test(url)) return {id: 610, state: "PENDING", html_url: "https://github.com/OpenCoven/example/pull/7#pullrequestreview-610"};
    if (/\/events$/.test(url)) return {id: 610, state: "APPROVED", html_url: "https://github.com/OpenCoven/example/pull/7#pullrequestreview-610"};
    return {id: 610, state: "DISMISSED"};
  }, async () => publishResultIfConfigured(config, task, resultPath, "token"));
  assert.equal(mutations[0].body.event, undefined);
  assert.equal(mutations[1].body.event, "APPROVE");
  assert.equal(mutations[2].body.event, "DISMISS");
  assert.match(mutations[3].url, /\/reviews\/610$/);
  assert.equal(task.publication_state, "published_review_dismissed_stale");
  assert.equal(task.publication_decision, "DISMISSED");
});

test("downgrades a decisive review when the base changes before pending review submission", async () => {
  const stateDir = tempStateDir();
  const config = testConfig(stateDir);
  const task = reviewTask("base-before-submit");
  prepareReviewWorkspace(config, task);
  const resultPath = join(stateDir, "result.json");
  writeFileSync(resultPath, JSON.stringify(completeReview()));
  let revisionReads = 0;
  const mutations: Array<{url: string; body: JsonObject}> = [];

  await withGithubApiMock((url, init) => {
    if (/\/pulls\/7$/.test(url)) {
      revisionReads += 1;
      return {
        head: {sha: "abc123"},
        base: {sha: revisionReads === 1 ? "base123" : "new-base"},
      };
    }
    if (init.method === "GET") return [];
    const body = init.body ? JSON.parse(String(init.body)) as JsonObject : {};
    mutations.push({url, body});
    if (/\/pulls\/7\/reviews$/.test(url)) {
      return {id: 611, state: "PENDING", html_url: "https://github.com/OpenCoven/example/pull/7#pullrequestreview-611"};
    }
    if (/\/events$/.test(url)) {
      return {id: 611, state: "COMMENTED", html_url: "https://github.com/OpenCoven/example/pull/7#pullrequestreview-611"};
    }
    return {id: 611};
  }, async () => publishResultIfConfigured(config, task, resultPath, "token"));

  const submission = mutations.find((mutation) => /\/events$/.test(mutation.url));
  assert.equal(revisionReads, 3);
  assert.equal(submission?.body.event, "COMMENT");
  assert.match(String(submission?.body.body || ""), /head or base changed before this review was submitted/);
  assert.equal(mutations.some((mutation) => /\/dismissals$/.test(mutation.url)), false);
  assert.equal(task.publication_state, "published_review_stale_comment");
  assert.equal(task.publication_decision, "COMMENT");
});

test("dismisses a decisive review when the base changes after submission", async () => {
  const stateDir = tempStateDir();
  const config = testConfig(stateDir);
  const task = reviewTask("base-after-submit");
  prepareReviewWorkspace(config, task);
  const resultPath = join(stateDir, "result.json");
  writeFileSync(resultPath, JSON.stringify(completeReview()));
  let revisionReads = 0;
  const mutations: Array<{url: string; body: JsonObject}> = [];

  await withGithubApiMock((url, init) => {
    if (/\/pulls\/7$/.test(url)) {
      revisionReads += 1;
      return {
        head: {sha: "abc123"},
        base: {sha: revisionReads < 3 ? "base123" : "new-base"},
      };
    }
    if (init.method === "GET") return [];
    const body = init.body ? JSON.parse(String(init.body)) as JsonObject : {};
    mutations.push({url, body});
    if (/\/pulls\/7\/reviews$/.test(url)) {
      return {id: 612, state: "PENDING", html_url: "https://github.com/OpenCoven/example/pull/7#pullrequestreview-612"};
    }
    if (/\/events$/.test(url)) {
      return {id: 612, state: "APPROVED", html_url: "https://github.com/OpenCoven/example/pull/7#pullrequestreview-612"};
    }
    return {id: 612, state: "DISMISSED"};
  }, async () => publishResultIfConfigured(config, task, resultPath, "token"));

  const submission = mutations.find((mutation) => /\/events$/.test(mutation.url));
  const dismissal = mutations.find((mutation) => /\/dismissals$/.test(mutation.url));
  assert.equal(revisionReads, 3);
  assert.equal(submission?.body.event, "APPROVE");
  assert.equal(dismissal?.body.event, "DISMISS");
  assert.match(String(dismissal?.body.message || ""), /head or base changed/);
  assert.equal(task.publication_state, "published_review_dismissed_stale");
  assert.equal(task.publication_decision, "DISMISSED");
});

test("retries a failed head-race dismissal until the stale decision is removed", async () => {
  const stateDir = tempStateDir();
  const config = testConfig(stateDir);
  const firstTask = reviewTask("head-race-retry");
  const retryTask = reviewTask("head-race-retry");
  prepareReviewWorkspace(config, firstTask);
  const resultPath = join(stateDir, "result.json");
  writeFileSync(resultPath, JSON.stringify(completeReview()));
  let firstHeadReads = 0;
  let reviewBody = "";
  let dismissalAttempts = 0;
  await withGithubApiMock((url, init) => {
    if (/\/pulls\/7$/.test(url)) {
      firstHeadReads += 1;
      return {head: {sha: firstHeadReads < 3 ? "abc123" : "new-head"}, base: {sha: "base123"}};
    }
    if (init.method === "GET") return [];
    if (/\/pulls\/7\/reviews$/.test(url)) {
      reviewBody = String((JSON.parse(String(init.body)) as JsonObject).body || "");
      return {id: 620, state: "PENDING", html_url: "https://github.com/OpenCoven/example/pull/7#pullrequestreview-620"};
    }
    if (/\/events$/.test(url)) return {id: 620, state: "APPROVED", html_url: "https://github.com/OpenCoven/example/pull/7#pullrequestreview-620"};
    if (/\/dismissals$/.test(url)) {
      dismissalAttempts += 1;
      return {httpStatus: 500, response: {message: "temporary failure"}};
    }
    return {id: 620};
  }, async () => publishResultIfConfigured(config, firstTask, resultPath, "token"));
  assert.equal(firstTask.publication_state, "publication_failed");

  await withGithubApiMock((url, init) => {
    if (/\/pulls\/7$/.test(url)) return {head: {sha: "new-head"}, base: {sha: "base123"}};
    if (init.method === "GET") return [{
      id: 620,
      state: "APPROVED",
      commit_id: "abc123",
      body: reviewBody,
      html_url: "https://github.com/OpenCoven/example/pull/7#pullrequestreview-620",
      user: covencatBot(),
    }];
    if (/\/dismissals$/.test(url)) {
      dismissalAttempts += 1;
      return {id: 620, state: "DISMISSED"};
    }
    return {id: 620};
  }, async () => publishResultIfConfigured(config, retryTask, resultPath, "token"));
  assert.equal(dismissalAttempts, 2);
  assert.equal(retryTask.publication_state, "published_review_dismissed_stale");
  assert.equal(retryTask.publication_decision, "DISMISSED");
});

test("recovery annotates an already-dismissed stale review without republishing it", async () => {
  const stateDir = tempStateDir();
  const config = testConfig(stateDir);
  const task = reviewTask("dismissed-stale-annotation");
  task.created_at = "2026-07-14T00:00:00Z";
  prepareReviewWorkspace(config, task);
  const result = completeReview();
  const resultPath = join(stateDir, "dismissed-stale-result.json");
  writeFileSync(resultPath, JSON.stringify(result));
  const identity = publicationIdentityFixture(task, result, true);
  const existingBody = `Dismissed stale review\n\n${signedPublicationMarker(identity, String(task.created_at))}`;
  const currentBody = `Current revision review\n\n${signedPublicationMarker("e".repeat(64), "2026-07-14T00:10:00Z")}`;
  let annotatedBody = "";
  const writes: string[] = [];
  await withGithubApiMock((url, init) => {
    if (/\/pulls\/7$/.test(url)) return {head: {sha: "new-head"}, base: {sha: "base123"}};
    if (init.method === "GET" && /\/pulls\/7\/reviews(?:\?|$)/.test(url)) return [
      {
        id: 740,
        state: "DISMISSED",
        commit_id: "abc123",
        body: existingBody,
        html_url: "https://github.com/OpenCoven/example/pull/7#pullrequestreview-740",
        user: covencatBot(),
      },
      {
        id: 741,
        state: "APPROVED",
        commit_id: "new-head",
        body: currentBody,
        html_url: "https://github.com/OpenCoven/example/pull/7#pullrequestreview-741",
        user: covencatBot(),
      },
    ];
    if (init.method === "GET") return [];
    writes.push(`${String(init.method)} ${url}`);
    annotatedBody = String((JSON.parse(String(init.body)) as JsonObject).body || "");
    return {id: 740, state: "DISMISSED", body: annotatedBody};
  }, async () => publishResultIfConfigured(config, task, resultPath, "token"));
  assert.deepEqual(writes, ["PUT https://api.github.com/repos/OpenCoven/example/pulls/7/reviews/740"]);
  assert.match(annotatedBody, /dismissed automatically because the PR head or base changed/);
  assert.match(annotatedBody, /<!-- covencat-publication-proof:[a-f0-9]{64} -->$/);
  assert.equal(task.publication_state, "publication_skipped_stale_revision");
  assert.equal(task.publication_decision, "DISMISSED");
});

test("a pre-submit stale COMMENT does not dismiss the prior decisive review", async () => {
  const stateDir = tempStateDir();
  const config = testConfig(stateDir);
  const firstTask = reviewTask("pre-submit-prior");
  const staleTask = reviewTask("pre-submit-stale");
  prepareReviewWorkspace(config, firstTask);
  prepareReviewWorkspace(config, staleTask);
  const resultPath = join(stateDir, "result.json");
  writeFileSync(resultPath, JSON.stringify(completeReview()));
  let secondRun = false;
  let secondHeadReads = 0;
  let nextId = 630;
  let activeId = 0;
  let dismissals = 0;
  await withGithubApiMock((url, init) => {
    if (/\/pulls\/7$/.test(url)) {
      if (!secondRun) return {head: {sha: "abc123"}, base: {sha: "base123"}};
      secondHeadReads += 1;
      return {head: {sha: secondHeadReads === 1 ? "abc123" : "new-head"}, base: {sha: "base123"}};
    }
    if (init.method === "GET") return [];
    if (/\/pulls\/7\/reviews$/.test(url)) {
      nextId += 1;
      activeId = nextId;
      return {id: activeId, state: "PENDING", html_url: `https://github.com/OpenCoven/example/pull/7#pullrequestreview-${activeId}`};
    }
    if (/\/events$/.test(url)) {
      const event = String((JSON.parse(String(init.body)) as JsonObject).event);
      return {id: activeId, state: event === "COMMENT" ? "COMMENTED" : "APPROVED", html_url: `https://github.com/OpenCoven/example/pull/7#pullrequestreview-${activeId}`};
    }
    if (/\/dismissals$/.test(url)) dismissals += 1;
    return {id: activeId};
  }, async () => {
    await publishResultIfConfigured(config, firstTask, resultPath, "token");
    secondRun = true;
    await publishResultIfConfigured(config, staleTask, resultPath, "token");
  });
  assert.equal(dismissals, 0);
  assert.equal(staleTask.publication_state, "published_review_stale_comment");
  assert.equal(staleTask.publication_decision, "COMMENT");
  assert.equal(staleTask.publication_supersession_state, "prior_decisive_review_retained_for_stale_replacement");
});

test("retains a prior decisive review until a complete replacement is published", async () => {
  const stateDir = tempStateDir();
  const config = testConfig(stateDir);
  const resultPath = join(stateDir, "result.json");
  const firstTask = reviewTask("chain-a");
  const secondTask = reviewTask("chain-b");
  const thirdTask = reviewTask("chain-c");
  for (const task of [firstTask, secondTask, thirdTask]) prepareReviewWorkspace(config, task);
  let nextId = 700;
  let activeId = 0;
  const dismissedIds: number[] = [];
  await withGithubApiMock((url, init) => {
    const read = githubReadFixture(url, init);
    if (read) return read;
    if (/\/pulls\/7\/reviews$/.test(url)) {
      nextId += 1;
      activeId = nextId;
      return {id: activeId, state: "PENDING", html_url: `https://github.com/OpenCoven/example/pull/7#pullrequestreview-${activeId}`};
    }
    if (/\/events$/.test(url)) {
      const event = String((JSON.parse(String(init.body)) as JsonObject).event);
      return {id: activeId, state: event === "COMMENT" ? "COMMENTED" : "APPROVED", html_url: `https://github.com/OpenCoven/example/pull/7#pullrequestreview-${activeId}`};
    }
    if (/\/dismissals$/.test(url)) {
      const reviewId = Number(url.match(/reviews\/(\d+)\/dismissals$/)?.[1] || 0);
      dismissedIds.push(reviewId);
      return {id: reviewId, state: "DISMISSED"};
    }
    return {id: activeId};
  }, async () => {
    writeFileSync(resultPath, JSON.stringify(completeReview()));
    await publishResultIfConfigured(config, firstTask, resultPath, "token");
    const incomplete = completeReview();
    (incomplete.review as JsonObject).limitations = ["Could not verify one environment-specific behavior."];
    writeFileSync(resultPath, JSON.stringify(incomplete));
    await publishResultIfConfigured(config, secondTask, resultPath, "token");
    assert.equal(secondTask.publication_decision, "COMMENT");
    assert.equal(secondTask.publication_supersession_state, "prior_decisive_review_retained_for_incomplete_replacement");
    assert.deepEqual(dismissedIds, []);
    writeFileSync(resultPath, JSON.stringify(completeReview()));
    await publishResultIfConfigured(config, thirdTask, resultPath, "token");
  });
  assert.deepEqual(dismissedIds, [701]);
  assert.equal(thirdTask.publication_supersession_state, "prior_decisive_review_dismissed");
});

test("a complete information-only COMMENT retains the prior decisive review", async () => {
  const stateDir = tempStateDir();
  const config = testConfig(stateDir);
  const firstTask = reviewTask("info-comment-first");
  const commentTask = reviewTask("info-comment-second");
  prepareReviewWorkspace(config, firstTask);
  prepareReviewWorkspace(config, commentTask);
  const resultPath = join(stateDir, "info-comment-result.json");
  let activeId = 730;
  let dismissals = 0;
  await withGithubApiMock((url, init) => {
    const read = githubReadFixture(url, init);
    if (read) return read;
    if (/\/pulls\/7\/reviews$/.test(url)) {
      activeId += 1;
      return {id: activeId, state: "PENDING", html_url: `https://github.com/OpenCoven/example/pull/7#pullrequestreview-${activeId}`};
    }
    if (/\/events$/.test(url)) {
      const event = String((JSON.parse(String(init.body)) as JsonObject).event);
      return {id: activeId, state: event === "COMMENT" ? "COMMENTED" : "APPROVED", html_url: `https://github.com/OpenCoven/example/pull/7#pullrequestreview-${activeId}`};
    }
    if (/\/dismissals$/.test(url)) {
      dismissals += 1;
      return {state: "DISMISSED"};
    }
    return {id: activeId};
  }, async () => {
    writeFileSync(resultPath, JSON.stringify(completeReview()));
    await publishResultIfConfigured(config, firstTask, resultPath, "token");
    writeFileSync(resultPath, JSON.stringify(completeReview([{
      severity: "info",
      file: "src/app.ts",
      line: 12,
      title: "Optional observation",
      body: "This does not require a code change.",
      recommendation: null,
    }])));
    await publishResultIfConfigured(config, commentTask, resultPath, "token");
  });
  assert.equal(commentTask.publication_decision, "COMMENT");
  assert.equal(commentTask.publication_supersession_state, "prior_decisive_review_retained_for_comment_replacement");
  assert.equal(dismissals, 0);
});

test("serializes concurrent publication attempts for the same identity", async () => {
  const stateDir = tempStateDir();
  const config = testConfig(stateDir);
  const firstTask = reviewTask("concurrent-run");
  const secondTask = reviewTask("concurrent-run");
  prepareReviewWorkspace(config, firstTask);
  const resultPath = join(stateDir, "result.json");
  writeFileSync(resultPath, JSON.stringify(completeReview()));
  let posts = 0;
  let publishedBody = "";
  await withGithubApiMock(async (url, init) => {
    if (init.method === "GET" && /\/pulls\/7$/.test(url)) {
      await new Promise((resolveDelay) => setTimeout(resolveDelay, 50));
      return {head: {sha: "abc123"}, base: {sha: "base123"}};
    }
    if (init.method === "GET" && /\/pulls\/7\/reviews\/407$/.test(url)) {
      return {id: 407, state: "APPROVED", body: publishedBody, html_url: "https://github.com/OpenCoven/example/pull/7#pullrequestreview-407", user: covencatBot()};
    }
    if (init.method === "GET") return [];
    if (/\/pulls\/7\/reviews$/.test(url)) {
      posts += 1;
      publishedBody = String((JSON.parse(String(init.body)) as JsonObject).body || "");
      return {id: 407, state: "PENDING", html_url: "https://github.com/OpenCoven/example/pull/7#pullrequestreview-407"};
    }
    return {id: 407, state: "APPROVED", body: publishedBody, html_url: "https://github.com/OpenCoven/example/pull/7#pullrequestreview-407"};
  }, async () => Promise.all([
    publishResultIfConfigured(config, firstTask, resultPath, "token"),
    publishResultIfConfigured(config, secondTask, resultPath, "token"),
  ]));
  assert.equal(posts, 1);
  assert.equal(secondTask.publication_state, "publication_skipped_duplicate");
});

test("redacts credentials and passes only allowlisted ambient environment keys", () => {
  const secretText = [
    "ghs_1234567890", "ghp_1234567890", "github_pat_1234567890",
    "sk-proj-1234567890", "Bearer topsecret", "eyJabc.def.ghi",
    "https://user:password@example.com/path",
    "-----BEGIN PRIVATE KEY-----\nprivate-data\n-----END PRIVATE KEY-----",
  ].join("\n");
  const redacted = redactTokenish(secretText);
  assert.doesNotMatch(redacted, /1234567890|topsecret|password|private-data|eyJabc/);
  const env = sanitizedRuntimeEnvironment({
    PATH: "/bin", LANG: "C.UTF-8", SSH_AUTH_SOCK: "/tmp/agent.sock",
    DATABASE_URL: "postgres://user:pass@db", AWS_ACCESS_KEY_ID: "AKIASECRET",
    GITHUB_WEBHOOK_SECRET: "webhook-secret",
  });
  assert.deepEqual(env, {PATH: "/bin", LANG: "C.UTF-8"});
});

test("keeps idempotency marker after truncating and redacts issue publication text", async () => {
  const stateDir = tempStateDir();
  const task: JsonObject = {
    task_id: "long-issue",
    repository: "OpenCoven/example",
    publication: {mode: "comment"},
    task: {issue_number: 12},
  };
  const resultPath = join(stateDir, "result.json");
  writeFileSync(resultPath, JSON.stringify({status: "failure", summary: `${"x".repeat(80_000)} ghs_1234567890`, pr_body: "", files_changed: [], commits: []}));
  let body = "";
  await withGithubApiMock((_url, init) => {
    if (init.method === "GET") return [];
    body = String((JSON.parse(String(init.body)) as JsonObject).body);
    return {id: 408, html_url: "https://github.com/OpenCoven/example/issues/12#issuecomment-408"};
  }, async () => publishResultIfConfigured(testConfig(stateDir), task, resultPath, "token"));
  assert.match(body, /<!-- covencat-publication:[a-f0-9]{64} -->/);
  assert.match(body, /<!-- covencat-publication-proof:[a-f0-9]{64} -->$/);
  assert.doesNotMatch(body, /ghs_1234567890/);
  assert.ok(body.length < 60_000);
});

test("concurrent signed deliveries initialize one task without overwriting the winner", async () => {
  const secret = "concurrent-delivery-secret";
  const stateDir = tempStateDir();
  const policyPath = join(stateDir, "policy.json");
  writeFileSync(policyPath, readFileSync(new URL("../config/example-policy.json", import.meta.url)));
  const config = createConfig({
    COVEN_GITHUB_STATE_DIR: stateDir,
    COVEN_GITHUB_POLICY_PATH: policyPath,
    GITHUB_WEBHOOK_SECRET: secret,
  }, process.cwd());
  const deliveryId = "concurrent-same-delivery";
  const firstPayload: JsonObject = {
    action: "labeled",
    installation: {id: 123456},
    repository: {id: 987654321, full_name: "OpenCoven/example", default_branch: "main"},
    issue: {
      number: 101,
      title: "First delivery payload",
      body: "The first caller owns initialization.",
      labels: [{name: "coven:fix"}],
    },
  };
  const secondPayload: JsonObject = {
    action: "labeled",
    installation: {id: 123456},
    repository: {id: 987654321, full_name: "OpenCoven/example", default_branch: "main"},
    issue: {
      number: 202,
      title: "Conflicting duplicate payload",
      body: "This duplicate must not overwrite the initialized task.",
      labels: [{name: "coven:fix"}],
    },
  };
  const request = (payload: JsonObject) => {
    const rawBody = Buffer.from(JSON.stringify(payload));
    return {
      method: "POST",
      path: "/webhook",
      headers: new Map([
        ["content-length", String(rawBody.length)],
        ["x-github-event", "issues"],
        ["x-github-delivery", deliveryId],
        ["x-hub-signature-256", signature(secret, rawBody)],
      ]),
      rawBody,
    };
  };

  const [first, duplicate] = await Promise.all([
    handleRequest(config, request(firstPayload), () => {}),
    handleRequest(config, request(secondPayload), () => {}),
  ]);

  assert.equal(first.status, 200);
  assert.equal(first.body.action, "accepted");
  assert.equal(duplicate.status, 200);
  assert.equal(duplicate.body.action, "duplicate_task_queued");
  assert.equal(duplicate.body.queued, true);
  assert.deepEqual(readdirSync(config.tasksDir), [`${deliveryId}.json`]);
  const task = JSON.parse(readFileSync(join(config.tasksDir, `${deliveryId}.json`), "utf8")) as JsonObject;
  assert.equal(task.state, "queued");
  assert.equal(task.attempts, 0);
  assert.equal(((task.task as JsonObject).issue_number), 101);
  assert.equal(((task.task as JsonObject).issue_title), "First delivery payload");
  const delivery = JSON.parse(readFileSync(join(config.deliveriesDir, `${deliveryId}.json`), "utf8")) as JsonObject;
  assert.equal(delivery.payload_hash, createHash("sha256").update(stableCompact(firstPayload)).digest("hex"));
});

test("transient revision reconciliation failure remains runnable and succeeds on retry", async () => {
  const stateDir = tempStateDir();
  const {privateKey} = generateKeyPairSync("rsa", {modulusLength: 2048});
  const config = createConfig({
    COVEN_GITHUB_STATE_DIR: stateDir,
    COVEN_GITHUB_POLICY_PATH: join(stateDir, "policy.json"),
    GITHUB_WEBHOOK_SECRET: "test-webhook-secret",
    GITHUB_APP_ID: "1234",
    COVEN_GITHUB_REVOCATION_EVENTS: "pull-request-and-push-verified",
    GITHUB_APP_PRIVATE_KEY: privateKey.export({type: "pkcs8", format: "pem"}).toString(),
  }, process.cwd());
  const policy: JsonObject = {
    familiar: {id: "reviewer"},
    publication: {mode: "comment"},
    bot_usernames: ["covencat[bot]"],
    enabled_triggers: ["pull_request.synchronize", "pull_request.edited", "pull_request.reopened", "push"],
  };
  const task = buildTaskFromEvent("pull_request", "transient-reconciliation", {
    action: "synchronize",
    installation: {id: 123456},
    repository: {id: 987654321, full_name: "OpenCoven/example"},
    pull_request: {
      number: 7,
      head: {sha: "current-head", ref: "feature"},
      base: {sha: "current-base", ref: "main"},
    },
  }, policy);
  task.policy_snapshot = policy;
  const taskFile = join(config.tasksDir, `${task.task_id}.json`);
  writeFileSync(taskFile, JSON.stringify(task));
  let tokenCalls = 0;
  let revisionReads = 0;

  await withGithubApiMock((url, init) => {
    if (/\/app\/installations\/123456\/access_tokens$/.test(url)) {
      tokenCalls += 1;
      return {token: `publication-token-${tokenCalls}`};
    }
    if (/\/pulls\/7$/.test(url)) {
      revisionReads += 1;
      if (revisionReads === 1) return {httpStatus: 502, response: {message: "temporary upstream failure"}};
      return {head: {sha: "current-head"}, base: {sha: "current-base"}};
    }
    if (init.method === "GET" && /\/pulls\/7\/reviews(?:\?|$)/.test(url)) return [];
    throw new Error(`Unexpected GitHub request: ${String(init.method)} ${url}`);
  }, async () => {
    const first = await runTask(config, String(task.task_id));
    assert.equal(first.state, "failed");
    assert.equal(first.attempts, 1);
    assert.equal(first.failure_category, "revision_reconciliation_failed");
    assert.equal(first.publication_state, "revision_reconciliation_retry_pending");
    assert.match(String(first.failure_detail), /temporary upstream failure/);
    assert.ok(Date.parse(String(first.retry_not_before)) > Date.now());
    assert.deepEqual(runnableTaskIds(config), [String(task.task_id)]);

    const callsBeforeImmediateRetry = tokenCalls + revisionReads;
    const deferred = await runTask(config, String(task.task_id));
    assert.equal(deferred.state, "failed");
    assert.equal(deferred.attempts, 1);
    assert.equal(tokenCalls + revisionReads, callsBeforeImmediateRetry);

    const retryable = JSON.parse(readFileSync(taskFile, "utf8")) as JsonObject;
    retryable.retry_not_before = "1970-01-01T00:00:00.000Z";
    writeFileSync(taskFile, JSON.stringify(retryable));
    const second = await runTask(config, String(task.task_id));
    assert.equal(second.state, "completed");
    assert.equal(second.attempts, 2);
    assert.equal(second.publication_state, "revision_reconciled_no_stale_reviews");
    assert.equal(second.retry_not_before, undefined);
    assert.deepEqual(runnableTaskIds(config), []);
  });

  assert.equal(tokenCalls, 2);
  assert.equal(revisionReads, 3);
  const persisted = JSON.parse(readFileSync(join(config.tasksDir, `${task.task_id}.json`), "utf8")) as JsonObject;
  assert.equal(persisted.state, "completed");
  assert.equal(persisted.failure_category, undefined);
  assert.equal(persisted.failure_detail, undefined);
});

test("signed actionless push enumerates open base pull requests and dismisses stale decisive reviews", async () => {
  const secret = "actionless-push-secret";
  const stateDir = tempStateDir();
  const policyPath = join(stateDir, "policy.json");
  writeFileSync(policyPath, JSON.stringify({
    version: 1,
    installations: {
      "123456": {
        repositories: {
          "987654321": {
            enabled_triggers: ["pull_request.synchronize", "pull_request.edited", "pull_request.reopened", "push"],
            bot_usernames: ["covencat[bot]"],
            familiar: {id: "reviewer"},
            publication: {mode: "comment"},
          },
        },
      },
    },
  }));
  const {privateKey} = generateKeyPairSync("rsa", {modulusLength: 2048});
  const config = createConfig({
    COVEN_GITHUB_STATE_DIR: stateDir,
    COVEN_GITHUB_POLICY_PATH: policyPath,
    GITHUB_WEBHOOK_SECRET: secret,
    COVEN_PUBLICATION_SIGNING_SECRET: "test-webhook-secret",
    GITHUB_APP_ID: "1234",
    COVEN_GITHUB_REVOCATION_EVENTS: "pull-request-and-push-verified",
    GITHUB_APP_PRIVATE_KEY: privateKey.export({type: "pkcs8", format: "pem"}).toString(),
  }, process.cwd());
  const payload = Buffer.from(JSON.stringify({
    ref: "refs/heads/main",
    before: "old-base",
    after: "new-base",
    commits: [{id: "new-base"}],
    installation: {id: 123456},
    repository: {id: 987654321, full_name: "OpenCoven/example", default_branch: "main"},
  }));
  const deliveryId = "actionless-push-reconciliation";
  const staleBody = `Stale review\n\n${signedBasePublicationMarker("a".repeat(64), "old-base", "2026-07-14T00:00:00Z")}`;
  const urls: string[] = [];
  const dismissed: number[] = [];

  await withGithubApiMock((url, init) => {
    urls.push(url);
    if (/\/app\/installations\/123456\/access_tokens$/.test(url)) return {token: "push-publication-token"};
    if (init.method === "GET" && /\/pulls\?/.test(url)) return [{number: 7}];
    if (/\/pulls\/7$/.test(url)) return {head: {sha: "feature-head"}, base: {sha: "new-base"}};
    if (init.method === "GET" && /\/pulls\/7\/reviews(?:\?|$)/.test(url)) return [{
      id: 770,
      state: "CHANGES_REQUESTED",
      commit_id: "feature-head",
      body: staleBody,
      html_url: "https://github.com/OpenCoven/example/pull/7#pullrequestreview-770",
      user: covencatBot(),
    }];
    if (init.method === "PUT" && /\/dismissals$/.test(url)) {
      dismissed.push(770);
      return {id: 770, state: "DISMISSED", body: staleBody};
    }
    if (init.method === "PUT" && /\/reviews\/770$/.test(url)) {
      return {id: 770, state: "DISMISSED", body: String((JSON.parse(String(init.body)) as JsonObject).body || "")};
    }
    throw new Error(`Unexpected GitHub request: ${String(init.method)} ${url}`);
  }, async () => {
    const response = await callWebhook(payload, {
      "X-GitHub-Event": "push",
      "X-GitHub-Delivery": deliveryId,
      "X-Hub-Signature-256": signature(secret, payload),
    }, "auto", config);
    assert.equal(response.status, 200);
    assert.equal(response.body.action, "accepted");
    assert.equal(response.body.state, "queued");
    const queued = JSON.parse(readFileSync(join(config.tasksDir, `${deliveryId}.json`), "utf8")) as JsonObject;
    assert.equal(queued.trigger, "base_branch_revision");
    assert.equal(((queued.task as JsonObject).kind), "reconcile_base_branch_push");
    assert.equal(((queued.task as JsonObject).base_ref), "main");
    const completed = await runTask(config, deliveryId);
    assert.equal(completed.state, "completed");
    assert.equal(completed.publication_state, "stale_decisive_reviews_dismissed");
    assert.deepEqual(completed.dismissed_review_ids, [770]);
  });

  const pullListUrl = urls.find((url) => /\/pulls\?/.test(url));
  assert.ok(pullListUrl);
  assert.equal(new URL(String(pullListUrl)).searchParams.get("state"), "open");
  assert.equal(new URL(String(pullListUrl)).searchParams.get("base"), "main");
  assert.deepEqual(dismissed, [770]);
});

test("base-only reconciliation dismisses base-aware and untracked legacy decisive reviews", async () => {
  const stateDir = tempStateDir();
  const {privateKey} = generateKeyPairSync("rsa", {modulusLength: 2048});
  const config = createConfig({
    COVEN_GITHUB_STATE_DIR: stateDir,
    COVEN_GITHUB_POLICY_PATH: join(stateDir, "policy.json"),
    GITHUB_WEBHOOK_SECRET: "test-webhook-secret",
    GITHUB_APP_ID: "1234",
    COVEN_GITHUB_REVOCATION_EVENTS: "pull-request-and-push-verified",
    GITHUB_APP_PRIVATE_KEY: privateKey.export({type: "pkcs8", format: "pem"}).toString(),
  }, process.cwd());
  const policy: JsonObject = {
    familiar: {id: "reviewer"},
    publication: {mode: "comment"},
    bot_usernames: ["covencat[bot]"],
    enabled_triggers: ["pull_request.synchronize", "pull_request.edited", "pull_request.reopened", "push"],
  };
  const task = buildTaskFromEvent("pull_request", "base-only-reconciliation", {
    action: "edited",
    installation: {id: 123456},
    repository: {id: 987654321, full_name: "OpenCoven/example"},
    pull_request: {
      number: 7,
      head: {sha: "same-head", ref: "feature"},
      base: {sha: "new-base", ref: "main"},
    },
  }, policy);
  task.policy_snapshot = policy;
  writeFileSync(join(config.tasksDir, `${task.task_id}.json`), JSON.stringify(task));
  const baseAwareBody = `Prior-base review\n\n${signedBasePublicationMarker("b".repeat(64), "old-base", "2026-07-14T00:00:00Z")}`;
  const legacyBody = `Legacy head-only review\n\n${signedPublicationMarker("c".repeat(64), "2026-07-14T00:01:00Z")}`;
  const dismissed: number[] = [];

  await withGithubApiMock((url, init) => {
    if (/\/app\/installations\/123456\/access_tokens$/.test(url)) return {token: "base-publication-token"};
    if (/\/pulls\/7$/.test(url)) return {head: {sha: "same-head"}, base: {sha: "new-base"}};
    if (init.method === "GET" && /\/pulls\/7\/reviews(?:\?|$)/.test(url)) return [
      {
        id: 780,
        state: "APPROVED",
        commit_id: "same-head",
        body: baseAwareBody,
        html_url: "https://github.com/OpenCoven/example/pull/7#pullrequestreview-780",
        user: covencatBot(),
      },
      {
        id: 781,
        state: "CHANGES_REQUESTED",
        commit_id: "same-head",
        body: legacyBody,
        html_url: "https://github.com/OpenCoven/example/pull/7#pullrequestreview-781",
        user: covencatBot(),
      },
    ];
    if (init.method === "PUT" && /\/dismissals$/.test(url)) {
      const id = Number(url.match(/\/reviews\/(\d+)\/dismissals$/)?.[1] || 0);
      dismissed.push(id);
      return {id, state: "DISMISSED"};
    }
    if (init.method === "PUT" && /\/reviews\/(?:780|781)$/.test(url)) {
      const id = Number(url.match(/\/reviews\/(\d+)$/)?.[1] || 0);
      return {id, state: "DISMISSED", body: String((JSON.parse(String(init.body)) as JsonObject).body || "")};
    }
    throw new Error(`Unexpected GitHub request: ${String(init.method)} ${url}`);
  }, async () => runTask(config, String(task.task_id)));

  assert.deepEqual(dismissed, [780, 781]);
  const persisted = JSON.parse(readFileSync(join(config.tasksDir, `${task.task_id}.json`), "utf8")) as JsonObject;
  assert.equal(persisted.state, "completed");
  assert.equal(persisted.publication_state, "stale_decisive_reviews_dismissed");
  assert.deepEqual(persisted.dismissed_review_ids, [780, 781]);
});

test("reconciliation repeats after a revision race and dismisses stale decisions from both passes", async () => {
  const stateDir = tempStateDir();
  const {privateKey} = generateKeyPairSync("rsa", {modulusLength: 2048});
  const config = createConfig({
    COVEN_GITHUB_STATE_DIR: stateDir,
    COVEN_GITHUB_POLICY_PATH: join(stateDir, "policy.json"),
    GITHUB_WEBHOOK_SECRET: "test-webhook-secret",
    GITHUB_APP_ID: "1234",
    COVEN_GITHUB_REVOCATION_EVENTS: "pull-request-and-push-verified",
    GITHUB_APP_PRIVATE_KEY: privateKey.export({type: "pkcs8", format: "pem"}).toString(),
  }, process.cwd());
  const policy: JsonObject = {
    familiar: {id: "reviewer"},
    publication: {mode: "comment"},
    bot_usernames: ["covencat[bot]"],
    enabled_triggers: ["pull_request.synchronize", "pull_request.edited", "pull_request.reopened", "push"],
  };
  const task = buildTaskFromEvent("pull_request", "revision-race-reconciliation", {
    action: "synchronize",
    installation: {id: 123456},
    repository: {id: 987654321, full_name: "OpenCoven/example"},
    pull_request: {
      number: 7,
      head: {sha: "head-a", ref: "feature"},
      base: {sha: "base-a", ref: "main"},
    },
  }, policy);
  task.policy_snapshot = policy;
  writeFileSync(join(config.tasksDir, `${task.task_id}.json`), JSON.stringify(task));
  const priorBody = `Older revision review\n\n${signedBasePublicationMarker("d".repeat(64), "base-zero", "2026-07-14T00:00:00Z")}`;
  const firstRevisionBody = `First observed revision review\n\n${signedBasePublicationMarker("e".repeat(64), "base-a", "2026-07-14T00:01:00Z")}`;
  const reviews: JsonObject[] = [
    {
      id: 790,
      state: "APPROVED",
      commit_id: "head-zero",
      body: priorBody,
      html_url: "https://github.com/OpenCoven/example/pull/7#pullrequestreview-790",
      user: covencatBot(),
    },
    {
      id: 791,
      state: "CHANGES_REQUESTED",
      commit_id: "head-a",
      body: firstRevisionBody,
      html_url: "https://github.com/OpenCoven/example/pull/7#pullrequestreview-791",
      user: covencatBot(),
    },
  ];
  let revisionReads = 0;
  let reviewReads = 0;
  const dismissed: number[] = [];

  await withGithubApiMock((url, init) => {
    if (/\/app\/installations\/123456\/access_tokens$/.test(url)) return {token: "race-publication-token"};
    if (/\/pulls\/7$/.test(url)) {
      revisionReads += 1;
      return revisionReads === 1
        ? {head: {sha: "head-a"}, base: {sha: "base-a"}}
        : {head: {sha: "head-b"}, base: {sha: "base-b"}};
    }
    if (init.method === "GET" && /\/pulls\/7\/reviews(?:\?|$)/.test(url)) {
      reviewReads += 1;
      return reviews;
    }
    if (init.method === "PUT" && /\/dismissals$/.test(url)) {
      const id = Number(url.match(/\/reviews\/(\d+)\/dismissals$/)?.[1] || 0);
      dismissed.push(id);
      return {id, state: "DISMISSED"};
    }
    if (init.method === "PUT" && /\/reviews\/(?:790|791)$/.test(url)) {
      const id = Number(url.match(/\/reviews\/(\d+)$/)?.[1] || 0);
      return {id, state: "DISMISSED", body: String((JSON.parse(String(init.body)) as JsonObject).body || "")};
    }
    throw new Error(`Unexpected GitHub request: ${String(init.method)} ${url}`);
  }, async () => runTask(config, String(task.task_id)));

  assert.equal(revisionReads, 4);
  assert.equal(reviewReads, 2);
  assert.deepEqual(dismissed, [790, 791]);
  const persisted = JSON.parse(readFileSync(join(config.tasksDir, `${task.task_id}.json`), "utf8")) as JsonObject;
  assert.equal(persisted.state, "completed");
  assert.deepEqual(persisted.reconciled_revision, {head_sha: "head-b", base_sha: "base-b"});
  assert.deepEqual(persisted.dismissed_review_ids, [790, 791]);
});

test("missing external-isolation attestation blocks before attempt creation or token use", async () => {
  const stateDir = tempStateDir();
  const config = createConfig({
    COVEN_GITHUB_STATE_DIR: stateDir,
    COVEN_GITHUB_POLICY_PATH: join(stateDir, "policy.json"),
    GITHUB_WEBHOOK_SECRET: "external-isolation-secret",
    COVEN_RUNTIME_ISOLATION: "bwrap",
    COVEN_RUNTIME_ROOTFS: join(stateDir, "unused-rootfs"),
  }, process.cwd());
  const task = buildTaskFromEvent("issues", "missing-external-isolation", {
    action: "labeled",
    installation: {id: 123456},
    repository: {
      id: 987654321,
      full_name: "OpenCoven/example",
      clone_url: "https://github.com/OpenCoven/example.git",
      default_branch: "main",
    },
    issue: {number: 303, title: "Isolation gate", body: "Do not spend credentials.", labels: [{name: "coven:fix"}]},
  }, {
    familiar: {id: "reviewer"},
    trigger_labels: ["coven:fix"],
    publication: {mode: "record_only"},
  });
  writeFileSync(join(config.tasksDir, `${task.task_id}.json`), JSON.stringify(task));
  let githubCalls = 0;

  const blocked = await withGithubApiMock(() => {
    githubCalls += 1;
    throw new Error("GitHub must not be called before external isolation is attested");
  }, async () => runTask(config, String(task.task_id)));

  assert.equal(githubCalls, 0);
  assert.equal(blocked.state, "blocked");
  assert.equal(blocked.attempts, 0);
  assert.equal(blocked.failure_category, "runtime_isolation_unavailable");
  assert.match(String(blocked.failure_detail), /COVEN_RUNTIME_EXTERNAL_ISOLATION/);
  assert.equal(existsSync(join(config.attemptsDir, String(task.task_id))), false);
  assert.equal(existsSync(join(config.workspacesDir, String(task.task_id))), false);
});

test("masked stale-review dismissal 404 remains retryable while exact or listed state is APPROVED", async () => {
  const stateDir = tempStateDir();
  const {privateKey} = generateKeyPairSync("rsa", {modulusLength: 2048});
  const config = createConfig({
    COVEN_GITHUB_STATE_DIR: stateDir,
    COVEN_GITHUB_POLICY_PATH: join(stateDir, "policy.json"),
    GITHUB_WEBHOOK_SECRET: "test-webhook-secret",
    GITHUB_APP_ID: "1234",
    COVEN_GITHUB_REVOCATION_EVENTS: "pull-request-and-push-verified",
    GITHUB_APP_PRIVATE_KEY: privateKey.export({type: "pkcs8", format: "pem"}).toString(),
  }, process.cwd());
  const policy: JsonObject = {
    familiar: {id: "reviewer"},
    publication: {mode: "comment"},
    bot_usernames: ["covencat[bot]"],
    enabled_triggers: ["pull_request.synchronize", "pull_request.edited", "pull_request.reopened", "push"],
  };
  const task = buildTaskFromEvent("pull_request", "masked-dismissal-404", {
    action: "synchronize",
    installation: {id: 123456},
    repository: {id: 987654321, full_name: "OpenCoven/example"},
    pull_request: {
      number: 7,
      head: {sha: "current-head", ref: "feature"},
      base: {sha: "current-base", ref: "main"},
    },
  }, policy);
  task.policy_snapshot = policy;
  const taskFile = join(config.tasksDir, `${task.task_id}.json`);
  writeFileSync(taskFile, JSON.stringify(task));
  const identity = "f".repeat(64);
  const reviewBody = `Still-active stale review\n\n${signedBasePublicationMarker(identity, "old-base", "2026-07-14T00:00:00Z")}`;
  const liveReview: JsonObject = {
    id: 800,
    state: "APPROVED",
    commit_id: "old-head",
    body: reviewBody,
    html_url: "https://github.com/OpenCoven/example/pull/7#pullrequestreview-800",
    user: covencatBot(),
  };
  const recordName = `${createHash("sha256").update("OpenCoven/example#7").digest("hex").slice(0, 24)}.json`;
  const recordPath = join(config.publicationsDir, recordName);
  const originalRecord: JsonObject = {
    identity,
    review_id: 800,
    review_url: liveReview.html_url,
    review_body: reviewBody,
    decision: "APPROVED",
    head_sha: "old-head",
    base_sha: "old-base",
  };
  writeFileSync(recordPath, JSON.stringify(originalRecord));
  let tokenCalls = 0;
  let dismissalAttempts = 0;
  let exactReviewReads = 0;
  let reviewListReads = 0;

  await withGithubApiMock((url, init) => {
    if (/\/app\/installations\/123456\/access_tokens$/.test(url)) {
      tokenCalls += 1;
      return {token: `masked-dismissal-token-${tokenCalls}`};
    }
    if (/\/pulls\/7$/.test(url)) return {head: {sha: "current-head"}, base: {sha: "current-base"}};
    if (init.method === "PUT" && /\/reviews\/800\/dismissals$/.test(url)) {
      dismissalAttempts += 1;
      return {httpStatus: 404, response: {message: "Not Found"}};
    }
    if (init.method === "GET" && /\/pulls\/7\/reviews\/800$/.test(url)) {
      exactReviewReads += 1;
      return exactReviewReads === 1
        ? liveReview
        : {httpStatus: 404, response: {message: "Not Found"}};
    }
    if (init.method === "GET" && /\/pulls\/7\/reviews(?:\?|$)/.test(url)) {
      reviewListReads += 1;
      return [liveReview];
    }
    throw new Error(`Unexpected GitHub request: ${String(init.method)} ${url}`);
  }, async () => {
    const exactReadFailure = await runTask(config, String(task.task_id));
    assert.equal(exactReadFailure.state, "failed");
    assert.equal(exactReadFailure.attempts, 1);
    assert.equal(exactReadFailure.publication_state, "revision_reconciliation_retry_pending");
    assert.equal(exactReadFailure.dismissed_review_ids, undefined);
    assert.ok(Date.parse(String(exactReadFailure.retry_not_before)) > Date.now());
    assert.deepEqual(runnableTaskIds(config), [String(task.task_id)]);

    const callsBeforeImmediateRetry = tokenCalls + dismissalAttempts + exactReviewReads + reviewListReads;
    const deferred = await runTask(config, String(task.task_id));
    assert.equal(deferred.state, "failed");
    assert.equal(deferred.attempts, 1);
    assert.equal(tokenCalls + dismissalAttempts + exactReviewReads + reviewListReads, callsBeforeImmediateRetry);

    const retryable = JSON.parse(readFileSync(taskFile, "utf8")) as JsonObject;
    retryable.retry_not_before = "1970-01-01T00:00:00.000Z";
    writeFileSync(taskFile, JSON.stringify(retryable));
    const relistFailure = await runTask(config, String(task.task_id));
    assert.equal(relistFailure.state, "failed");
    assert.equal(relistFailure.attempts, 2);
    assert.equal(relistFailure.publication_state, "revision_reconciliation_retry_pending");
    assert.equal(relistFailure.dismissed_review_ids, undefined);
    assert.equal(relistFailure.reconciliation_results, undefined);
    assert.deepEqual(runnableTaskIds(config), [String(task.task_id)]);
  });

  assert.equal(tokenCalls, 2);
  assert.equal(dismissalAttempts, 2);
  assert.equal(exactReviewReads, 2);
  assert.equal(reviewListReads, 3);
  assert.deepEqual(JSON.parse(readFileSync(recordPath, "utf8")), originalRecord);
});

test("signed retry links matching orphan tasks without overwrite and rejects hash conflicts", async () => {
  const secret = "orphan-delivery-secret";
  const stateDir = tempStateDir();
  const config = testConfig(stateDir, secret);
  const payloadObject: JsonObject = {
    action: "labeled",
    installation: {id: 123456},
    repository: {id: 987654321, full_name: "OpenCoven/example", default_branch: "main"},
    issue: {number: 404, title: "Recover transaction", body: "Link existing task state.", labels: [{name: "coven:fix"}]},
  };
  const payload = Buffer.from(JSON.stringify(payloadObject));
  const payloadDigest = createHash("sha256").update(stableCompact(payloadObject)).digest("hex");
  const cases: JsonObject[] = [
    {
      task_id: "orphan-running-delivery",
      delivery_id: "orphan-running-delivery",
      delivery_payload_hash: payloadDigest,
      state: "running",
      attempts: 4,
      workspace_path: "/preserved/running/workspace",
      publication_state: "not_started",
      custom_runtime_field: "must-survive",
    },
    {
      task_id: "orphan-terminal-delivery",
      delivery_id: "orphan-terminal-delivery",
      delivery_payload_hash: payloadDigest,
      state: "completed",
      attempts: 5,
      runtime_exit_code: 0,
      result_path: "/preserved/final/result.json",
      publication_state: "published_review",
      publication_review_id: 12345,
    },
  ];

  for (const originalTask of cases) {
    const deliveryId = String(originalTask.delivery_id);
    const taskFile = join(config.tasksDir, `${deliveryId}.json`);
    writeFileSync(taskFile, JSON.stringify(originalTask));
    const response = await callWebhook(payload, {
      "X-GitHub-Event": "issues",
      "X-GitHub-Delivery": deliveryId,
      "X-Hub-Signature-256": signature(secret, payload),
    }, "auto", config);
    assert.equal(response.status, 200);
    assert.equal(response.body.recovered_orphan_task, true);
    assert.equal(response.body.action, originalTask.state === "running" ? "duplicate_task_queued" : "duplicate_ignored");
    assert.deepEqual(JSON.parse(readFileSync(taskFile, "utf8")), originalTask);
    const delivery = JSON.parse(readFileSync(join(config.deliveriesDir, `${deliveryId}.json`), "utf8")) as JsonObject;
    assert.equal(delivery.task_id, deliveryId);
    assert.equal(delivery.payload_hash, payloadDigest);
    assert.equal(delivery.state, originalTask.state);
    assert.equal(delivery.routing_result, "recovered_orphan_task");
  }

  const conflictId = "orphan-conflicting-delivery";
  const conflictTask: JsonObject = {
    task_id: conflictId,
    delivery_id: conflictId,
    delivery_payload_hash: "0".repeat(64),
    state: "running",
    attempts: 9,
    failure_detail: "preserve conflicting state",
  };
  const conflictFile = join(config.tasksDir, `${conflictId}.json`);
  writeFileSync(conflictFile, JSON.stringify(conflictTask));
  const conflict = await callWebhook(payload, {
    "X-GitHub-Event": "issues",
    "X-GitHub-Delivery": conflictId,
    "X-Hub-Signature-256": signature(secret, payload),
  }, "auto", config);
  assert.equal(conflict.status, 409);
  assert.equal(conflict.body.action, "conflict");
  assert.equal(conflict.body.reason, "delivery_task_conflict");
  assert.deepEqual(JSON.parse(readFileSync(conflictFile, "utf8")), conflictTask);
  assert.equal(existsSync(join(config.deliveriesDir, `${conflictId}.json`)), false);
});

test("masked 404 while superseding an active decisive review persists a pending dismissal", async () => {
  const stateDir = tempStateDir();
  const config = createConfig({
    COVEN_GITHUB_STATE_DIR: stateDir,
    COVEN_GITHUB_POLICY_PATH: join(stateDir, "policy.json"),
    GITHUB_WEBHOOK_SECRET: "test-webhook-secret",
    COVEN_GITHUB_REVOCATION_EVENTS: "pull-request-and-push-verified",
  }, process.cwd());
  const task = reviewTask("masked-supersession-404");
  task.created_at = "2026-07-14T00:10:00Z";
  const resultPath = join(stateDir, "masked-supersession-result.json");
  writeFileSync(resultPath, JSON.stringify(completeReview()));
  Object.assign(task, {
    state: "completed",
    result_path: resultPath,
    publication_state: "publication_pending",
    installation_id: 123456,
    repository_id: 987654321,
  });
  prepareReviewWorkspace(config, task);
  const taskFile = join(config.tasksDir, `${task.task_id}.json`);
  writeFileSync(taskFile, JSON.stringify(task));
  const priorIdentity = "9".repeat(64);
  const priorBody = `Prior active approval\n\n${signedBasePublicationMarker(priorIdentity, "base123", "2026-07-14T00:00:00Z")}`;
  const priorReview: JsonObject = {
    id: 901,
    state: "APPROVED",
    commit_id: "abc123",
    submitted_at: "2026-07-14T00:00:00Z",
    body: priorBody,
    html_url: "https://github.com/OpenCoven/example/pull/7#pullrequestreview-901",
    user: covencatBot(),
  };
  let tokenCalls = 0;
  let reviewListReads = 0;
  let exactPriorReads = 0;
  let dismissalAttempts = 0;
  let createdReviews = 0;
  let submittedReviews = 0;
  let warnedCurrentBody = "";

  await withGithubApiMock((url, init) => {
    if (init.method === "GET" && /\/pulls\/7$/.test(url)) {
      return {head: {sha: "abc123"}, base: {sha: "base123"}};
    }
    if (init.method === "GET" && /\/pulls\/7\/reviews\/901$/.test(url)) {
      exactPriorReads += 1;
      return priorReview;
    }
    if (init.method === "GET" && /\/pulls\/7\/reviews(?:\?|$)/.test(url)) {
      reviewListReads += 1;
      return [priorReview];
    }
    if (init.method === "POST" && /\/pulls\/7\/reviews$/.test(url)) {
      createdReviews += 1;
      return {
        id: 902,
        state: "PENDING",
        html_url: "https://github.com/OpenCoven/example/pull/7#pullrequestreview-902",
      };
    }
    if (init.method === "POST" && /\/pulls\/7\/reviews\/902\/events$/.test(url)) {
      submittedReviews += 1;
      assert.equal((JSON.parse(String(init.body)) as JsonObject).event, "APPROVE");
      return {
        id: 902,
        state: "APPROVED",
        html_url: "https://github.com/OpenCoven/example/pull/7#pullrequestreview-902",
      };
    }
    if (init.method === "PUT" && /\/pulls\/7\/reviews\/901\/dismissals$/.test(url)) {
      dismissalAttempts += 1;
      return {httpStatus: 404, response: {message: "Not Found"}};
    }
    if (init.method === "PUT" && /\/pulls\/7\/reviews\/902$/.test(url)) {
      warnedCurrentBody = String((JSON.parse(String(init.body)) as JsonObject).body || "");
      return {id: 902, state: "APPROVED", body: warnedCurrentBody};
    }
    throw new Error(`Unexpected GitHub request: ${String(init.method)} ${url}`);
  }, async () => resumeTaskPublication(config, String(task.task_id), () => {}, async () => {
    tokenCalls += 1;
    return "masked-supersession-token";
  }));

  assert.equal(tokenCalls, 1);
  assert.equal(reviewListReads, 1);
  assert.equal(exactPriorReads, 1);
  assert.equal(dismissalAttempts, 1);
  assert.equal(createdReviews, 1);
  assert.equal(submittedReviews, 1);
  assert.match(warnedCurrentBody, /did not permit covencat to dismiss the prior decisive review/);
  const persisted = JSON.parse(readFileSync(taskFile, "utf8")) as JsonObject;
  assert.equal(persisted.state, "completed");
  assert.equal(persisted.publication_state, "publication_failed");
  assert.equal(persisted.publication_supersession_state, "prior_decisive_review_dismissal_failed");
  assert.notEqual(persisted.publication_supersession_state, "prior_decisive_review_dismissed");
  assert.match(String(persisted.publication_error), /1 prior decisive review dismissal remains? pending/);
  assert.ok(Date.parse(String(persisted.retry_not_before)) > Date.now());
  const recordName = `${createHash("sha256").update("OpenCoven/example#7").digest("hex").slice(0, 24)}.json`;
  const record = JSON.parse(readFileSync(join(config.publicationsDir, recordName), "utf8")) as JsonObject;
  assert.equal(record.supersession_pending, true);
  assert.deepEqual(record.pending_dismissals, [{
    id: 901,
    state: "APPROVED",
    html_url: "https://github.com/OpenCoven/example/pull/7#pullrequestreview-901",
    identity: priorIdentity,
  }]);
});

test("reconciliation honors persisted Retry-After deadlines for 429 and 403 responses", async () => {
  const {privateKey} = generateKeyPairSync("rsa", {modulusLength: 2048});
  const privateKeyPem = privateKey.export({type: "pkcs8", format: "pem"}).toString();
  const policy: JsonObject = {
    familiar: {id: "reviewer"},
    publication: {mode: "comment"},
    bot_usernames: ["covencat[bot]"],
    enabled_triggers: ["pull_request.synchronize", "pull_request.edited", "pull_request.reopened", "push"],
  };

  for (const status of [429, 403]) {
    const stateDir = tempStateDir();
    const config = createConfig({
      COVEN_GITHUB_STATE_DIR: stateDir,
      COVEN_GITHUB_POLICY_PATH: join(stateDir, "policy.json"),
      GITHUB_WEBHOOK_SECRET: "test-webhook-secret",
      GITHUB_APP_ID: "1234",
      GITHUB_APP_PRIVATE_KEY: privateKeyPem,
      COVEN_GITHUB_REVOCATION_EVENTS: "pull-request-and-push-verified",
    }, process.cwd());
    const task = buildTaskFromEvent("pull_request", `retry-after-${status}`, {
      action: "synchronize",
      installation: {id: 123456},
      repository: {id: 987654321, full_name: "OpenCoven/example"},
      pull_request: {
        number: 7,
        head: {sha: "current-head", ref: "feature"},
        base: {sha: "current-base", ref: "main"},
      },
    }, policy);
    task.policy_snapshot = policy;
    const taskFile = join(config.tasksDir, `${task.task_id}.json`);
    writeFileSync(taskFile, JSON.stringify(task));
    let apiCalls = 0;
    let tokenCalls = 0;
    let rateLimitReturned = false;
    const startedAt = Date.now();

    await withGithubApiMock((url, init) => {
      apiCalls += 1;
      if (/\/app\/installations\/123456\/access_tokens$/.test(url)) {
        tokenCalls += 1;
        return {token: `retry-after-token-${status}-${tokenCalls}`};
      }
      if (/\/pulls\/7$/.test(url)) {
        if (!rateLimitReturned) {
          rateLimitReturned = true;
          return {
            httpStatus: status,
            response: {message: status === 429 ? "rate limited" : "secondary rate limit"},
            headers: {"retry-after": "120"},
          };
        }
        return {head: {sha: "current-head"}, base: {sha: "current-base"}};
      }
      if (init.method === "GET" && /\/pulls\/7\/reviews(?:\?|$)/.test(url)) return [];
      throw new Error(`Unexpected GitHub request: ${String(init.method)} ${url}`);
    }, async () => {
      const failed = await runTask(config, String(task.task_id));
      assert.equal(failed.state, "failed");
      assert.equal(failed.attempts, 1);
      assert.equal(failed.publication_state, "revision_reconciliation_retry_pending");
      const retryDeadline = Date.parse(String(failed.retry_not_before));
      assert.ok(retryDeadline >= startedAt + 119_000);
      assert.ok(retryDeadline <= Date.now() + 121_000);

      const callsBeforeImmediateRetry = apiCalls;
      const deferred = await runTask(config, String(task.task_id));
      assert.equal(deferred.state, "failed");
      assert.equal(deferred.attempts, 1);
      assert.equal(deferred.retry_not_before, failed.retry_not_before);
      assert.equal(apiCalls, callsBeforeImmediateRetry);

      const retryable = JSON.parse(readFileSync(taskFile, "utf8")) as JsonObject;
      retryable.retry_not_before = "1970-01-01T00:00:00.000Z";
      writeFileSync(taskFile, JSON.stringify(retryable));
      const completed = await runTask(config, String(task.task_id));
      assert.equal(completed.state, "completed");
      assert.equal(completed.attempts, 2);
      assert.equal(completed.publication_state, "revision_reconciled_no_stale_reviews");
      assert.equal(completed.retry_not_before, undefined);
    });

    assert.equal(tokenCalls, 2);
    assert.equal(apiCalls, 6);
  }
});
