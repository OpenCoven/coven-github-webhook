import {createSign} from "node:crypto";
import {readFileSync} from "node:fs";

const appId = String(process.env.GITHUB_APP_ID || "").trim();
const keyPath = String(process.env.GITHUB_APP_PRIVATE_KEY_PATH || "").trim();
const policyPath = String(process.env.COVEN_GITHUB_POLICY_PATH || "").trim();
if (!appId || !keyPath || !policyPath) throw new Error("GitHub App verification inputs are missing");

const base64url = (value) => Buffer.from(value).toString("base64url");
const now = Math.floor(Date.now() / 1000);
const header = base64url(JSON.stringify({alg: "RS256", typ: "JWT"}));
const payload = base64url(JSON.stringify({iat: now - 60, exp: now + 540, iss: appId}));
const signer = createSign("RSA-SHA256");
signer.update(`${header}.${payload}`);
const signature = signer.sign(readFileSync(keyPath)).toString("base64url");
const jwt = `${header}.${payload}.${signature}`;

async function github(path) {
  const response = await fetch(`https://api.github.com${path}`, {
    headers: {
      Accept: "application/vnd.github+json",
      Authorization: `Bearer ${jwt}`,
      "User-Agent": "covencat-deployment-verifier",
      "X-GitHub-Api-Version": "2022-11-28",
    },
  });
  if (!response.ok) throw new Error(`GitHub App verification failed at ${path}: HTTP ${response.status}`);
  return response.json();
}

const policy = JSON.parse(readFileSync(policyPath, "utf8"));
const installationIds = Object.keys(policy.installations || {});
if (installationIds.length !== 1 || !/^\d+$/.test(installationIds[0])) {
  throw new Error("Production policy must select exactly one installation for this verifier");
}

const [app, installation] = await Promise.all([
  github("/app"),
  github(`/app/installations/${installationIds[0]}`),
]);
const permissions = installation.permissions || app.permissions || {};
const events = new Set(installation.events || app.events || []);
const levels = {read: 1, write: 2, admin: 3};
for (const [name, required] of Object.entries({contents: "write", pull_requests: "write", issues: "write", metadata: "read"})) {
  if ((levels[permissions[name]] || 0) < levels[required]) {
    throw new Error(`GitHub App permission ${name}:${required} is required`);
  }
}
for (const event of ["pull_request", "push"]) {
  if (!events.has(event)) throw new Error(`GitHub App event subscription is missing: ${event}`);
}

process.stdout.write(`${JSON.stringify({
  ok: true,
  installation_id: installationIds[0],
  permissions: {
    contents: permissions.contents,
    pull_requests: permissions.pull_requests,
    issues: permissions.issues,
    metadata: permissions.metadata,
  },
  required_events: ["pull_request", "push"],
})}\n`);
