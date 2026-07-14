import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  buildTaskFromEvent,
  createConfig,
  githubRequestAllPages,
  handleRequest,
  normalizeReviewPublication,
  patchEvidenceIncomplete,
  publishResultIfConfigured,
  redactTokenish,
  sanitizedRuntimeEnvironment,
  type JsonObject,
} from "../src/adapter.js";

type GithubMockResult = JsonObject | JsonObject[] | {httpStatus: number; response: JsonObject | JsonObject[]};

async function withGithubApiMock<T>(handler: (url: string, init: RequestInit) => GithubMockResult | Promise<GithubMockResult>, work: () => Promise<T>): Promise<T> {
  const original = globalThis.fetch;
  globalThis.fetch = async (input, init) => {
    const result = await handler(String(input), init || {});
    if (!Array.isArray(result) && "httpStatus" in result) {
      return new Response(JSON.stringify(result.response), {status: Number(result.httpStatus)});
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
    policy_snapshot: {bot_usernames: ["covencat[bot]"]},
    target: {kind: "pull_request", pr_number: 7},
    task: {pr_number: 7},
    review_evidence: {
      head_sha: "abc123",
      workspace_head_sha: "abc123",
      publication_workspace_head_sha: "abc123",
      publication_workspace_clean: true,
      changed_file_count: 2,
      expected_changed_file_count: 2,
      incomplete_patch_files: [],
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
  if (/\/pulls\/7$/.test(url)) return {head: {sha: "abc123"}};
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

  await withGithubApiMock((url, init) => {
    calls.push({url, init});
    const read = githubReadFixture(url, init);
    if (read) return read;
    return {id: 101, html_url: "https://github.com/OpenCoven/example/pull/7#pullrequestreview-101"};
  }, async () => {
    await publishResultIfConfigured(config, task, resultPath, "token");
    await publishResultIfConfigured(config, task, resultPath, "token");
  });

  assert.equal(calls.length, 6);
  assert.match(calls[2].url, /\/pulls\/7\/reviews$/);
  const draft = JSON.parse(String(calls[2].init.body)) as JsonObject;
  assert.equal(draft.event, undefined);
  assert.equal(draft.commit_id, "abc123");
  assert.equal((draft.comments as JsonObject[]).length, 1);
  assert.match(calls[4].url, /\/pulls\/7\/reviews\/101\/events$/);
  const submission = JSON.parse(String(calls[4].init.body)) as JsonObject;
  assert.equal(submission.event, "REQUEST_CHANGES");
  assert.ok(calls[2].init.signal instanceof AbortSignal);
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

test("a newer review names the prior covencat publication as superseded", async () => {
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
  assert.match(bodies[1], /supersedes/);
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
  await withGithubApiMock((_url, init) => {
    methods.push(String(init.method));
    if (init.method === "GET") return [];
    return {id: 301, html_url: "https://github.com/OpenCoven/example/issues/11#issuecomment-301"};
  }, async () => {
    await publishResultIfConfigured(testConfig(stateDir), task, resultPath, "token");
    await publishResultIfConfigured(testConfig(stateDir), task, resultPath, "token");
  });
  assert.deepEqual(methods, ["GET", "POST"]);
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
    workspace_head_sha: "abc123",
    publication_workspace_head_sha: "abc123",
    publication_workspace_clean: true,
    changed_file_count: 1,
    expected_changed_file_count: 1,
    incomplete_patch_files: [],
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

test("recovers a review identity from GitHub after local publication state is lost", async () => {
  const firstState = tempStateDir();
  const firstConfig = testConfig(firstState);
  const firstTask = reviewTask("recovered-run");
  prepareReviewWorkspace(firstConfig, firstTask);
  const firstResult = join(firstState, "result.json");
  writeFileSync(firstResult, JSON.stringify(completeReview()));
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

  const secondState = tempStateDir();
  const secondConfig = testConfig(secondState);
  const secondTask = reviewTask("recovered-run");
  prepareReviewWorkspace(secondConfig, secondTask);
  const secondResult = join(secondState, "result.json");
  writeFileSync(secondResult, JSON.stringify(completeReview()));
  let posts = 0;
  await withGithubApiMock((url, init) => {
    if (/\/pulls\/7$/.test(url)) return {head: {sha: "abc123"}};
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
    if (/\/pulls\/7$/.test(url)) return {head: {sha: "abc123"}};
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
  await withGithubApiMock((url, init) => {
    const read = githubReadFixture(url, init);
    if (read) return read;
    if (init.method === "POST" && /\/pulls\/7\/reviews$/.test(url)) {
      posts += 1;
      nextReviewId += 1;
      activeReviewId = nextReviewId;
      return {id: activeReviewId, state: "PENDING", html_url: `https://github.com/OpenCoven/example/pull/7#pullrequestreview-${activeReviewId}`};
    }
    if (init.method === "POST") {
      return {id: activeReviewId, state: "APPROVED", html_url: `https://github.com/OpenCoven/example/pull/7#pullrequestreview-${activeReviewId}`};
    }
    if (/\/dismissals$/.test(url)) {
      dismissals += 1;
      if (dismissals === 1) return {httpStatus: 500, response: {message: "temporary failure"}};
      assert.equal((JSON.parse(String(init.body)) as JsonObject).event, "DISMISS");
      return {state: "DISMISSED"};
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
  let writes = 0;
  await withGithubApiMock((url, init) => {
    if (/\/pulls\/7$/.test(url)) return {head: {sha: "abc123"}};
    if (init.method === "GET") return [{
      id: 601,
      state: "APPROVED",
      commit_id: "abc123",
      submitted_at: "2026-07-14T12:00:00Z",
      body: `current review\n\n${signedPublicationMarker("b".repeat(64))}`,
      user: covencatBot(),
    }];
    writes += 1;
    return {id: 602};
  }, async () => publishResultIfConfigured(config, task, resultPath, "token"));
  assert.equal(writes, 0);
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
    if (/\/pulls\/7$/.test(url)) return {head: {sha: "abc123"}};
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
    if (/\/pulls\/7$/.test(url)) return {head: {sha: "head-h"}};
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
    if (/\/pulls\/7$/.test(url)) return {head: {sha: "abc123"}};
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
      return {head: {sha: headReads < 3 ? "abc123" : "new-head"}};
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
      return {head: {sha: firstHeadReads < 3 ? "abc123" : "new-head"}};
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
    if (/\/pulls\/7$/.test(url)) return {head: {sha: "new-head"}};
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
      if (!secondRun) return {head: {sha: "abc123"}};
      secondHeadReads += 1;
      return {head: {sha: secondHeadReads === 1 ? "abc123" : "new-head"}};
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

test("serializes concurrent publication attempts for the same identity", async () => {
  const stateDir = tempStateDir();
  const config = testConfig(stateDir);
  const firstTask = reviewTask("concurrent-run");
  const secondTask = reviewTask("concurrent-run");
  prepareReviewWorkspace(config, firstTask);
  const resultPath = join(stateDir, "result.json");
  writeFileSync(resultPath, JSON.stringify(completeReview()));
  let posts = 0;
  await withGithubApiMock(async (url, init) => {
    const read = githubReadFixture(url, init);
    if (read) {
      if (/\/pulls\/7$/.test(url)) await new Promise((resolveDelay) => setTimeout(resolveDelay, 50));
      return read;
    }
    if (/\/pulls\/7\/reviews$/.test(url)) posts += 1;
    return {id: 407, html_url: "https://github.com/OpenCoven/example/pull/7#pullrequestreview-407"};
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
