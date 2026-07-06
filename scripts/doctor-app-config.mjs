#!/usr/bin/env node
import {existsSync, readFileSync} from "node:fs";
import {join} from "node:path";

import {createConfig} from "../dist/src/adapter.js";

function finding(level, field, message, next) {
  return {level, field, message, next};
}

function hasPem(value) {
  return /-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(value || "");
}

function loadJson(path) {
  try {
    return JSON.parse(readFileSync(path, "utf8"));
  } catch {
    return null;
  }
}

const config = createConfig(process.env, process.cwd());
const findings = [];

if (!config.appId) {
  findings.push(finding("error", "GITHUB_APP_ID", "missing GitHub App ID", "Set GITHUB_APP_ID or run through 1Password with an App ID env ref."));
} else if (!/^\d+$/.test(config.appId)) {
  findings.push(finding("error", "GITHUB_APP_ID", "GitHub App ID must be numeric", "Use the numeric App ID from the GitHub App settings page."));
}

if (!config.webhookSecret) {
  findings.push(finding("error", "GITHUB_WEBHOOK_SECRET", "missing webhook secret", "Set GITHUB_WEBHOOK_SECRET from the GitHub App webhook secret."));
}

if (!config.privateKeyPem && !existsSync(config.privateKeyPath)) {
  findings.push(finding("error", "GITHUB_APP_PRIVATE_KEY", "missing GitHub App private key", "Set GITHUB_APP_PRIVATE_KEY from 1Password or GITHUB_APP_PRIVATE_KEY_PATH to a PEM file."));
} else if (config.privateKeyPem && !hasPem(config.privateKeyPem)) {
  findings.push(finding("error", "GITHUB_APP_PRIVATE_KEY", "private key env var does not look like a PEM", "Store the full downloaded GitHub App private key PEM in 1Password."));
} else if (!config.privateKeyPem) {
  const key = readFileSync(config.privateKeyPath, "utf8");
  if (!hasPem(key)) {
    findings.push(finding("error", "GITHUB_APP_PRIVATE_KEY_PATH", "private key file does not look like a PEM", "Point GITHUB_APP_PRIVATE_KEY_PATH at the downloaded GitHub App private key."));
  }
}

const policy = loadJson(config.policyPath);
if (!policy) {
  findings.push(finding("error", "COVEN_GITHUB_POLICY_PATH", "policy file is missing or invalid JSON", "Copy config/example-policy.json and replace the installation/repository IDs."));
} else {
  const installations = policy.installations || {};
  const installationIds = Object.keys(installations);
  if (!installationIds.length) {
    findings.push(finding("error", "policy.installations", "policy has no installation routes", "Add the GitHub App installation ID and repository ID."));
  }
  if (installationIds.includes("123456")) {
    findings.push(finding("error", "policy.installations", "policy still uses placeholder installation ID 123456", "Replace it with the real installation ID."));
  }
  for (const installationId of installationIds) {
    const repos = installations[installationId]?.repositories || {};
    if (!Object.keys(repos).length) {
      findings.push(finding("error", "policy.repositories", `installation ${installationId} has no repositories`, "Add at least one repository ID route."));
    }
    if (Object.keys(repos).includes("987654321")) {
      findings.push(finding("error", "policy.repositories", "policy still uses placeholder repository ID 987654321", "Replace it with the real repository ID."));
    }
  }
}

if (!process.env.COVEN_CODE_BIN && !config.demoMode) {
  findings.push(finding("warning", "COVEN_CODE_BIN", "COVEN_CODE_BIN is not set", "Set it to the coven-code binary path before running real tasks."));
}

const errors = findings.filter((item) => item.level === "error");
const output = {
  ok: errors.length === 0,
  demo_mode: config.demoMode,
  checked: {
    app_id: Boolean(config.appId),
    webhook_secret: Boolean(config.webhookSecret),
    private_key: Boolean(config.privateKeyPem || existsSync(config.privateKeyPath)),
    policy_path: config.policyPath,
    state_dir: config.stateDir,
  },
  findings,
};

console.log(JSON.stringify(output, null, 2));
process.exit(errors.length ? 1 : 0);
