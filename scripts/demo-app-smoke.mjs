#!/usr/bin/env node
import {createHmac} from "node:crypto";
import {mkdtempSync, readFileSync, writeFileSync} from "node:fs";
import {tmpdir} from "node:os";
import {join} from "node:path";

import {createConfig} from "../dist/src/adapter.js";
import {createWebhookServer} from "../dist/src/server.js";

const root = new URL("..", import.meta.url).pathname;
const stateDir = mkdtempSync(join(tmpdir(), "coven-github-demo-"));
const policyPath = join(stateDir, "policy.json");
const secret = "local-demo-webhook-secret";
const deliveryId = "demo-delivery-issues-labeled";
const port = Number.parseInt(process.env.PORT || "3137", 10);

writeFileSync(
  policyPath,
  readFileSync(new URL("../config/example-policy.json", import.meta.url)),
);

const payload = {
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
};
const body = Buffer.from(JSON.stringify(payload));
const signature = `sha256=${createHmac("sha256", secret).update(body).digest("hex")}`;

const config = createConfig(
  {
    COVEN_GITHUB_DEMO_MODE: "1",
    COVEN_GITHUB_STATE_DIR: stateDir,
    COVEN_GITHUB_POLICY_PATH: policyPath,
    GITHUB_WEBHOOK_SECRET: secret,
  },
  root,
);

const server = createWebhookServer(config);
await new Promise((resolve) => server.listen(port, "127.0.0.1", resolve));

try {
  const response = await fetch(`http://127.0.0.1:${port}/webhook`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-GitHub-Event": "issues",
      "X-GitHub-Delivery": deliveryId,
      "X-Hub-Signature-256": signature,
    },
    body,
  });
  const result = await response.json();
  const delivery = JSON.parse(readFileSync(join(stateDir, "deliveries", `${deliveryId}.json`), "utf8"));
  const task = JSON.parse(readFileSync(join(stateDir, "tasks", `${deliveryId}.json`), "utf8"));
  const demoResult = JSON.parse(readFileSync(task.result_path, "utf8"));

  console.log(JSON.stringify({
    ok: response.ok,
    status: response.status,
    response: result,
    state_dir: stateDir,
    delivery: {
      id: delivery.delivery_id,
      event: delivery.event,
      routing_result: delivery.routing_result,
      state: delivery.state,
      repository: delivery.repository,
    },
    task: {
      id: task.task_id,
      state: task.state,
      trigger: task.trigger,
      familiar: task.familiar,
      issue_number: task.task?.issue_number,
      publication_state: task.publication_state,
      session_brief_path: task.session_brief_path,
      result_path: task.result_path,
    },
    result: {
      status: demoResult.status,
      summary: demoResult.summary,
      evidence_status: demoResult.review?.evidence_status,
      tests_run: demoResult.review?.tests_run,
      limitations: demoResult.review?.limitations,
    },
  }, null, 2));
} finally {
  await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
}
