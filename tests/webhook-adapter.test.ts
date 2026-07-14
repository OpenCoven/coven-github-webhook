import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  buildTaskFromEvent,
  createConfig,
  handleRequest,
  normalizeReviewPublication,
  publishResultIfConfigured,
  type JsonObject,
} from "../src/adapter.js";

async function withGithubApiMock<T>(handler: (url: string, init: RequestInit) => JsonObject, work: () => Promise<T>): Promise<T> {
  const original = globalThis.fetch;
  globalThis.fetch = async (input, init) => new Response(JSON.stringify(handler(String(input), init || {})), {status: 200});
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
    target: {kind: "pull_request", pr_number: 7},
    task: {pr_number: 7},
    review_evidence: {
      head_sha: "abc123",
      changed_files: ["src/app.ts", "tests/app.test.ts"],
      changed_file_lines: [{path: "src/app.ts", right_lines: [12]}],
    },
  };
}

function completeReview(findings: JsonObject[] = []): JsonObject {
  return {
    status: "success",
    summary: "Reviewed the pull request.",
    files_changed: [],
    commits: [],
    review: {
      mode: "pull_request",
      evidence_status: "complete",
      reviewed_files: ["src/app.ts"],
      supporting_files: ["tests/app.test.ts"],
      findings,
      tests_run: [{command: "npm test", status: "passed", output_summary: "all tests passed"}],
      limitations: [],
    },
  };
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
      GITHUB_APP_PRIVATE_KEY: "-----BEGIN PRIVATE KEY-----\nexample\n-----END PRIVATE KEY-----",
    },
    process.cwd(),
  );

  assert.equal(config.privateKeyPem, "-----BEGIN PRIVATE KEY-----\nexample\n-----END PRIVATE KEY-----");
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

test("publishes a native change-request review with inline findings and skips a retry", async () => {
  const stateDir = tempStateDir();
  const config = testConfig(stateDir);
  const task = reviewTask();
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

  await withGithubApiMock((url, init) => {
    calls.push({url, init});
    return {id: 101, html_url: "https://github.com/OpenCoven/example/pull/7#pullrequestreview-101"};
  }, async () => {
    await publishResultIfConfigured(config, task, resultPath, "token");
    await publishResultIfConfigured(config, task, resultPath, "token");
  });

  assert.equal(calls.length, 1);
  assert.match(calls[0].url, /\/pulls\/7\/reviews$/);
  const body = JSON.parse(String(calls[0].init.body)) as JsonObject;
  assert.equal(body.event, "REQUEST_CHANGES");
  assert.equal((body.comments as JsonObject[]).length, 1);
  assert.equal(task.publication_state, "publication_skipped_duplicate");
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
  const resultPath = join(stateDir, "result.json");
  writeFileSync(resultPath, JSON.stringify(result));
  let published = "";
  await withGithubApiMock((_url, init) => {
    published = String(init.body);
    return {id: 102, html_url: "https://github.com/OpenCoven/example/pull/7#pullrequestreview-102"};
  }, async () => publishResultIfConfigured(testConfig(stateDir), task, resultPath, "token"));

  assert.match(published, /"event":"COMMENT"/);
  assert.match(published, /Publication validation/);
  assert.match(published, /https:\/\/github\.com\/OpenCoven\/example\/blob\/abc123\/src\/app\.ts/);
});

test("a newer review names the prior covencat publication as superseded", async () => {
  const stateDir = tempStateDir();
  const resultPath = join(stateDir, "result.json");
  writeFileSync(resultPath, JSON.stringify(completeReview()));
  const bodies: string[] = [];
  let id = 200;
  await withGithubApiMock((_url, init) => {
    bodies.push(String(init.body));
    id += 1;
    return {id, html_url: `https://github.com/OpenCoven/example/pull/7#pullrequestreview-${id}`};
  }, async () => {
    await publishResultIfConfigured(testConfig(stateDir), reviewTask("first-run"), resultPath, "token");
    await publishResultIfConfigured(testConfig(stateDir), reviewTask("newer-run"), resultPath, "token");
  });

  assert.equal(bodies.length, 2);
  assert.match(bodies[1], /supersedes/);
  assert.match(bodies[1], /pullrequestreview-201/);
});

test("keeps a finding in the review body when its line is not in the captured diff", async () => {
  const stateDir = tempStateDir();
  const task = reviewTask("invalid-inline-location");
  const resultPath = join(stateDir, "result.json");
  writeFileSync(resultPath, JSON.stringify(completeReview([{severity: "high", file: "src/app.ts", line: 99, title: "Out-of-diff finding"}])));
  let published = "";
  await withGithubApiMock((_url, init) => {
    published = String(init.body);
    return {id: 250, html_url: "https://github.com/OpenCoven/example/pull/7#pullrequestreview-250"};
  }, async () => publishResultIfConfigured(testConfig(stateDir), task, resultPath, "token"));
  const body = JSON.parse(published) as JsonObject;
  assert.equal(body.comments, undefined);
  assert.match(String(body.body), /Findings without valid inline locations/);
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
  await withGithubApiMock((_url, init) => {
    methods.push(String(init.method));
    return {id: 301, html_url: "https://github.com/OpenCoven/example/issues/11#issuecomment-301"};
  }, async () => {
    await publishResultIfConfigured(testConfig(stateDir), task, resultPath, "token");
    await publishResultIfConfigured(testConfig(stateDir), task, resultPath, "token");
  });
  assert.deepEqual(methods, ["POST", "PATCH"]);
  assert.equal(task.publication_comment_id, 301);
});
