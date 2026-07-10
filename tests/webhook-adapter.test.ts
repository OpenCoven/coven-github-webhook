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
  publicationCommentBody,
  type JsonObject,
} from "../src/adapter.js";

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
  assert.equal(task.trigger, "issue_assigned");
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

test("new issue creation is ignored unless a supported trigger is enabled", () => {
  const task = buildTaskFromEvent(
    "issues",
    "delivery-issue-opened",
    {
      action: "opened",
      installation: {id: 123456},
      repository: {
        id: 987654321,
        full_name: "OpenCoven/example",
        clone_url: "https://github.com/OpenCoven/example.git",
        default_branch: "main",
      },
      issue: {
        number: 43,
        title: "Installer is slow",
        body: "A diagnostic issue, not a bot task.",
        labels: [],
        assignees: [],
      },
    } as JsonObject,
    {
      enabled_triggers: [
        "issues.labeled",
        "issue_comment.created",
        "pull_request_review_comment.created",
      ],
      trigger_labels: ["coven:fix"],
      bot_usernames: ["coven-cody[bot]"],
      familiar: {
        id: "cody",
        display_name: "Cody",
        model: "openai/gpt-5.5",
        skills: [],
      },
      publication: {mode: "record_only"},
    } as JsonObject,
  );

  assert.equal(task.state, "ignored");
  assert.equal(task.ignored_reason, "unsupported_issue_action");
});

test("publication body links screenshot-style file mentions to GitHub blobs", () => {
  const body = publicationCommentBody(
    {
      task_id: "task-file-links",
      repository: "OpenCoven/coven-github-webhook",
      default_branch: "main",
      review_evidence: {
        head_sha: "abc123def456",
      },
    },
    {
      status: "success",
      summary: [
        "### Files inspected",
        "",
        "- `src/lib/server/skills-directory.ts`",
        "- `Read src/lib/server/skill-scan.ts`",
        "- Read src/lib/server/skill-scan.ts - passed: inspected adapter implementation.",
        "- Read AGENTS.md - passed: reviewed guidance.",
        "- Fixed a bug, e.g. the parser broke.",
        "- In other words, i.e. no bogus abbreviation links.",
        "- Mentioned foo.bar.baz.qux in prose.",
        "- Grep for https://github.com/OpenCoven/coven-github-webhook/blob/main/src/adapter.ts and tests_run[].output_summary.",
        "- `README.md:12`",
        "- `README.md:12-14`",
        "- `tests_run[].output_summary`",
        "- `pnpm test`",
        "",
        "```ts",
        "`src/not-linked-inside-fence.ts`",
        "```",
      ].join("\n"),
      review: {
        supporting_files: ["AGENTS.md"],
      },
    },
  );

  assert.match(
    body,
    /\[`src\/lib\/server\/skills-directory\.ts`\]\(https:\/\/github\.com\/OpenCoven\/coven-github-webhook\/blob\/abc123def456\/src\/lib\/server\/skills-directory\.ts\)/,
  );
  assert.match(
    body,
    /`Read` \[`src\/lib\/server\/skill-scan\.ts`\]\(https:\/\/github\.com\/OpenCoven\/coven-github-webhook\/blob\/abc123def456\/src\/lib\/server\/skill-scan\.ts\)/,
  );
  assert.match(
    body,
    /Read \[`src\/lib\/server\/skill-scan\.ts`\]\(https:\/\/github\.com\/OpenCoven\/coven-github-webhook\/blob\/abc123def456\/src\/lib\/server\/skill-scan\.ts\) - passed/,
  );
  assert.match(
    body,
    /Read \[`AGENTS\.md`\]\(https:\/\/github\.com\/OpenCoven\/coven-github-webhook\/blob\/abc123def456\/AGENTS\.md\) - passed/,
  );
  assert.match(body, /https:\/\/github\.com\/OpenCoven\/coven-github-webhook\/blob\/main\/src\/adapter\.ts/);
  assert.match(body, /e\.g\. the parser broke/);
  assert.match(body, /i\.e\. no bogus abbreviation links/);
  assert.match(body, /foo\.bar\.baz\.qux in prose/);
  assert.doesNotMatch(body, /\[`e\.g`\]/);
  assert.doesNotMatch(body, /\[`i\.e`\]/);
  assert.doesNotMatch(body, /\[`foo\.bar\.baz\.qux`\]/);
  assert.match(
    body,
    /\[`README\.md:12`\]\(https:\/\/github\.com\/OpenCoven\/coven-github-webhook\/blob\/abc123def456\/README\.md#L12\)/,
  );
  assert.match(
    body,
    /\[`README\.md:12-14`\]\(https:\/\/github\.com\/OpenCoven\/coven-github-webhook\/blob\/abc123def456\/README\.md#L12-L14\)/,
  );
  assert.match(body, /- `pnpm test`/);
  assert.match(body, /- `tests_run\[\]\.output_summary`/);
  assert.doesNotMatch(body, /\[`tests_run\[\]\.output_summary`\]/);
  assert.doesNotMatch(body, /blob\/main\/\[`src\/adapter\.ts`\]/);
  assert.match(body, /`src\/not-linked-inside-fence\.ts`/);
  assert.doesNotMatch(body, /\[`src\/not-linked-inside-fence\.ts`\]/);
});

test("publication body links structured review file lists and findings", () => {
  const body = publicationCommentBody(
    {
      task_id: "task-structured-links",
      repository: "OpenCoven/coven-github-webhook",
      default_branch: "main",
      review_evidence: {
        head_sha: "feedface",
        changed_files: ["src/app.ts"],
        changed_file_count: 1,
      },
    },
    {
      status: "success",
      summary: "Done.",
      review: {
        mode: "review",
        evidence_status: "complete",
        reviewed_files: ["src/app.ts"],
        supporting_files: ["tests/app.test.ts"],
        findings: [
          {
            severity: "medium",
            file: "src/app.ts",
            line: 7,
            title: "Example finding",
          },
        ],
        no_findings_reason: "Checked `tests/app.test.ts` with `npm test`.",
        tests_run: [
          {
            command: "Read src/app.ts",
            status: "passed",
            output_summary: "inspected `tests/app.test.ts` coverage.",
          },
          {
            command: "npm test",
            status: "passed",
          },
        ],
      },
    },
  );

  assert.match(body, /\[`src\/app\.ts`\]\(https:\/\/github\.com\/OpenCoven\/coven-github-webhook\/blob\/feedface\/src\/app\.ts\)/);
  assert.match(body, /\[`tests\/app\.test\.ts`\]\(https:\/\/github\.com\/OpenCoven\/coven-github-webhook\/blob\/feedface\/tests\/app\.test\.ts\)/);
  assert.match(body, /\[`src\/app\.ts:7`\]\(https:\/\/github\.com\/OpenCoven\/coven-github-webhook\/blob\/feedface\/src\/app\.ts#L7\)/);
  assert.match(body, /`Read` \[`src\/app\.ts`\]\(https:\/\/github\.com\/OpenCoven\/coven-github-webhook\/blob\/feedface\/src\/app\.ts\): `passed`/);
  assert.match(body, /with `npm test`/);
  assert.match(body, /- `npm test`: `passed`/);
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
