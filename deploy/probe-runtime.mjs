import {mkdirSync, rmSync} from "node:fs";
import {randomUUID} from "node:crypto";

import {
  createConfig,
  probeRuntimeIsolation,
  runtimeIsolationIssue,
} from "/app/dist/src/adapter.js";

const config = createConfig();
const configurationIssue = runtimeIsolationIssue(config);
if (configurationIssue) throw new Error(configurationIssue);

const attemptDir = `${config.attemptsDir}/deployment-probe-${randomUUID()}`;
mkdirSync(attemptDir, {mode: 0o700});
try {
  const probeIssue = probeRuntimeIsolation(config, attemptDir);
  if (probeIssue) throw new Error(probeIssue);
  process.stdout.write(`${JSON.stringify({ok: true, isolation: "bwrap", network_probe: "none"})}\n`);
} finally {
  rmSync(attemptDir, {recursive: true, force: true});
}
