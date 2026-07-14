# coven-github webhook

Hosted webhook deployment bundle for the Coven GitHub integration.

This repository tracks the TypeScript webhook adapter used to receive GitHub App
events, capture review context, run `coven-code`, and publish structured review
results back to GitHub.

The adapter is deployment-specific. It is not the canonical Rust worker
implementation; it exists so hosted webhook behavior can be reviewed,
reproduced, and changed through PRs instead of server-only edits.

Long-running tasks execute outside the HTTP thread so GitHub deliveries are
acknowledged promptly and health endpoints stay responsive. Queued or
interrupted tasks are discovered again when the service starts. Native review
deployments must subscribe the GitHub App to both `pull_request` and `push`, and
must enable `pull_request.synchronize`, `pull_request.edited`,
`pull_request.reopened`, and the actionless `push` trigger. These deliveries
reconcile stale decisive reviews after head changes, base retargeting, reopening,
or new commits on a PR's base branch. A `publication.mode=comment` route that
lacks any of these safety triggers fails closed instead of publishing native PR
reviews.

## Files

- `src/adapter.ts` - webhook handler, task router, task runner, PR evidence
  capture, Codex-backed headless runtime invocation, and comment publisher.
- `src/server.ts` - Node HTTP entrypoint for `/`, `/healthz`, and `/webhook`.
- `tests/webhook-adapter.test.ts` - parity coverage for signature handling,
  request body edge cases, and task routing guards.
- `config/example-policy.json` - example installation/repository policy that
  connects a GitHub App install to a familiar route.
- `docs/coven-github-connection.md` - operator guide for connecting this
  TypeScript deployment bundle to the canonical `coven-github` app manifest.
- `scripts/demo-app-smoke.mjs` - local signed-delivery demo for the example
  policy route.
- `scripts/smoke-webhook.sh` - local HMAC signature smoke test for a running
  webhook endpoint.

## Runtime inputs

The deployment expects secrets and mutable state to be supplied outside git:

- `GITHUB_APP_ID`
- `GITHUB_WEBHOOK_SECRET` or `WEBHOOK_SECRET`
- `COVEN_PUBLICATION_SIGNING_SECRET` - optional dedicated HMAC key for review
  identity markers; defaults to the webhook secret for compatibility
- `COVEN_PUBLICATION_PREVIOUS_SIGNING_SECRETS` - comma-separated prior marker
  keys retained only during rotation/reconciliation
- `GITHUB_APP_PRIVATE_KEY_PATH` or `.coven-github-private-key.pem`
- `COVEN_GITHUB_STATE_DIR`
- `COVEN_GITHUB_POLICY_PATH`
- `COVEN_RUNTIME_ISOLATION=bwrap` - required for every non-demo task; unset is
  fail-closed and never falls back to direct execution
- `COVEN_RUNTIME_EXTERNAL_ISOLATION=network-egress-and-resource-limits-verified`
  - mandatory declaration that the deployment independently enforces egress,
  CPU, memory, PID, and disk/scratch limits
- `COVEN_GITHUB_REVOCATION_EVENTS=pull-request-and-push-verified` - set only
  after verifying the installed App's live `pull_request` and `push`
  subscriptions; native PR publication fails closed without it
- `COVEN_BWRAP_BIN` - absolute host path to bubblewrap (defaults to
  `/usr/bin/bwrap`)
- `COVEN_RUNTIME_ROOTFS` - dedicated credential-free runtime rootfs
- `COVEN_CODE_BIN` - absolute coven-code path inside that rootfs
- `COVEN_RUNTIME_NETWORK=shared` - explicit opt-in required when the Codex
  provider needs network access; the default is `none`
- Automatic review and repair are repository-policy controls, not ambient
  environment switches. `autoreview.enabled` and `repair.enabled` must each be
  opted into explicitly; `kill_switch` stops new routing and repair pushes.
- Codex OAuth tokens under the deployed account's `.coven-code` directory

Do not commit private keys, webhook secrets, OAuth tokens, generated task state,
workspaces, or attempt artifacts.

Real tasks never execute directly as the webhook account. Before minting a
GitHub token, the adapter runs a bubblewrap probe and verifies read-only input,
writable workspace/output mounts, a private PID namespace, no network for
validation, and a dedicated rootfs that does not contain adapter state or
credentials. A missing binary, rootfs, executable, or usable user namespace
records the task as `runtime_isolation_unavailable` with no direct fallback.
`publication.mode=record_only` is not an isolation control.

The runtime rootfs must contain the configured `coven-code`, `git`, and shell
executables plus their libraries, CA/DNS files, and approved runtime assets. It
must not contain the GitHub App key, webhook state, policy, parent home, or Codex
token store. The private PID namespace receives an empty `/proc`, avoiding host
procfs exposure and nested procfs-mount authority. The runtime receives only its
dedicated model credential; it never
receives a GitHub token or Git askpass helper. Shared networking is not an
egress-confidentiality boundary, so use a dedicated, revocable model credential
and an externally enforced allowlist that blocks loopback, LAN, and metadata
services. The adapter refuses real tasks unless the external network/resource
isolation declaration is present.

The current runtime passes that model credential to `coven-code`; an untrusted
checkout can therefore try to consume or encode it through the model channel
even when ordinary egress is filtered. Treat this release as trusted-repository
only. Public/untrusted pull requests require a separately constrained worker and
a quota-limited credential broker that never exposes a reusable model token to
the repository process. Do not set the external-isolation declaration for that
use case until those controls exist.

## Local runtime

Install dependencies, build TypeScript, and start the webhook service:

```bash
npm ci
npm run build
WEBHOOK_SECRET="replace-with-local-secret" npm start
```

For local development without a build step:

```bash
WEBHOOK_SECRET="replace-with-local-secret" npm run dev
```

The server listens on `PORT` or `3000` by default.

## Local smoke test

Run the adapter, then verify signature handling:

```bash
WEBHOOK_SECRET="replace-with-local-secret" \
  scripts/smoke-webhook.sh http://localhost:3000/webhook
```

The smoke test proves that unsigned requests and bad signatures are rejected,
while a correctly HMAC-signed GitHub `ping` delivery is accepted without needing
`coven-code` or a GitHub installation token.

## Verification

```bash
npm test
npm run build
npm run doctor:app
npm run smoke:app
```

## Policy

The default checked-in policy is empty:

```json
{"version": 1, "installations": {}}
```

Deployments should provide `coven-github-policy.json` through
`COVEN_GITHUB_POLICY_PATH`. That file is intentionally ignored because it is
environment-specific.

Every route with `publication.mode=comment` must include all native-review
safety triggers: `pull_request.synchronize`, `pull_request.edited`,
`pull_request.reopened`, and `push`. The `push` key is actionless; do not write
`push.`. Both the `pull_request` and `push` webhook events must also be enabled
on the installed GitHub App. Missing policy coverage is a configuration error
and native publication remains fail closed. After verifying the live App
registration, set
`COVEN_GITHUB_REVOCATION_EVENTS=pull-request-and-push-verified`; this declaration
is required in addition to the policy trigger list.

Start from [`config/example-policy.json`](config/example-policy.json) and the
connection guide in
[`docs/coven-github-connection.md`](docs/coven-github-connection.md).

## Current behavior

- Emits headless contract v2 session briefs.
- Supports explicit `COVEN_GITHUB_DEMO_MODE=1` local app smoke runs that verify
  signed delivery -> policy route -> delivery/task/result state without calling
  GitHub or `coven-code`.
- Captures PR checkout metadata and changed-file patches before invoking
  `coven-code`, including paginated file lists and patch-completeness checks.
- Publishes PR results as native GitHub reviews: complete no-finding evidence
  approves, actionable findings request changes, and incomplete or
  contradictory evidence is published as a comment review. Findings are made
  inline only when their captured diff location is valid; all other findings
  remain in the review body. Decisive reviews are bound to the captured commit
  and require full changed-file coverage, a clean matching checkout, and
  verified passing test evidence. They are created pending, then submitted only
  after fresh head and base checks; a concurrent revision change causes a
  COMMENT downgrade or automatic dismissal. Passing claims are decisive only
  when they match successful host-captured validation receipts. Validation and
  post-run Git checks execute in a second credential-free, network-disabled
  sandbox.
- Uses repository-scoped installation tokens: parent Git gets only
  `contents:read`, PR evidence gets read authority, and publication write
  authority is minted only after isolated execution has finished. An opted-in
  repair mints a separate short-lived token with only `contents:write` and
  `pull_requests:read`; the model never receives it.
- Persists `publication_pending` before GitHub writes and resumes interrupted
  publication on startup or duplicate webhook delivery without rerunning the
  agent.
- Persists publication identities and review/comment IDs in the configured
  state directory, reconciles HMAC-signed App-authored identities with GitHub,
  and serializes publication per PR so retries and concurrent runs do not
  duplicate output.
  Newer reviews link to superseded covencat output and dismiss its prior
  decisive state when GitHub permits it.
- Publishes non-PR task results and operational notices as issue comments,
  including structured `reviewed_files`, `supporting_files`, findings, test
  evidence, no-findings rationale, and limitations.
- With explicit `autoreview.enabled`, routes opened, ready-for-review, reopened,
  and synchronized pull-request revisions by repository, PR number, and exact
  head SHA. Drafts remain excluded unless `include_drafts` is enabled.
- With separate `repair.enabled`, an evidence-complete REQUEST_CHANGES review
  may launch a file-write-only hosted repair. The trusted host rejects forks,
  protected branches and paths, oversized or unrelated diffs, stale heads, and
  failed validation; it then creates a Covencat-attributed non-force commit and
  queues a fresh review of the new SHA. The loop stops after the configured
  `max_attempts` (clamped to 1-3) or on repeated findings or non-progress.
