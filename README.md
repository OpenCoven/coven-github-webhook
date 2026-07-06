# coven-github webhook

Hosted webhook deployment bundle for the Coven GitHub integration.

This repository tracks the TypeScript webhook adapter used to receive GitHub App
events, capture review context, run `coven-code`, and publish structured review
results back to GitHub.

The adapter is deployment-specific. It is not the canonical Rust worker
implementation; it exists so hosted webhook behavior can be reviewed,
reproduced, and changed through PRs instead of server-only edits.

## Files

- `src/adapter.ts` - webhook handler, task router, task runner, PR evidence
  capture, Codex-backed headless runtime invocation, and comment publisher.
- `src/server.ts` - Node HTTP entrypoint for `/`, `/healthz`, and `/webhook`.
- `tests/webhook-adapter.test.ts` - parity coverage for signature handling,
  request body edge cases, and task routing guards.
- `scripts/smoke-webhook.sh` - local HMAC signature smoke test for a running
  webhook endpoint.

## Runtime inputs

The deployment expects secrets and mutable state to be supplied outside git:

- `GITHUB_APP_ID`
- `GITHUB_WEBHOOK_SECRET` or `WEBHOOK_SECRET`
- `GITHUB_APP_PRIVATE_KEY_PATH` or `.coven-github-private-key.pem`
- `COVEN_GITHUB_STATE_DIR`
- `COVEN_GITHUB_POLICY_PATH`
- `COVEN_CODE_BIN`
- `COVEN_REVIEW_FIX_LOOPS` - optional bounded review-fix loop count, clamped
  between `0` and `5`; defaults to `0` so hosted repair loops are opt-in
- Codex OAuth tokens under the deployed account's `.coven-code` directory

Do not commit private keys, webhook secrets, OAuth tokens, generated task state,
workspaces, or attempt artifacts.

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
```

## Policy

The default checked-in policy is empty:

```json
{"version": 1, "installations": {}}
```

Deployments should provide `coven-github-policy.json` through
`COVEN_GITHUB_POLICY_PATH`. That file is intentionally ignored because it is
environment-specific.

## Current behavior

- Emits headless contract v2 session briefs.
- Captures PR checkout metadata and changed-file patches before invoking
  `coven-code`.
- Publishes visible structured review evidence, including `reviewed_files`,
  `supporting_files`, findings, test evidence, no-findings rationale, and
  limitations.
- When `COVEN_REVIEW_FIX_LOOPS` is greater than `0`, reruns `coven-code` with
  prior structured review findings as explicit repair instructions until no
  findings remain or the configured loop count is exhausted.
