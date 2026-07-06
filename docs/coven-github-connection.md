# Connecting to coven-github

`coven-github-webhook` is the TypeScript deployment bundle for the
[`OpenCoven/coven-github`](https://github.com/OpenCoven/coven-github) product
surface. It receives GitHub App webhooks, verifies signatures, applies
installation/repository routing policy, and starts `coven-code` headless runs.

Use the canonical `coven-github` repo for the product spec, GitHub App
permissions, event list, headless contract, and hosted/self-hosted operating
model. Use this repo when you want the lightweight Node deployment entrypoint.

## App Registration

Register the GitHub App with the manifest from `coven-github`:

- `OpenCoven/coven-github/docs/app-manifest.json`

Set the manifest webhook URL to this service:

```text
https://your-host/webhook
```

The manifest subscribes to the events this adapter can route:

- `issues`
- `issue_comment`
- `pull_request_review`
- `pull_request_review_comment`
- `check_suite`
- `check_run`

After creating the App, keep these values outside git:

- App ID -> `GITHUB_APP_ID`
- Webhook secret -> `GITHUB_WEBHOOK_SECRET`
- Private key PEM -> `GITHUB_APP_PRIVATE_KEY`, or private key PEM path ->
  `GITHUB_APP_PRIVATE_KEY_PATH`

For 1Password-backed local runs, copy
`.env.1password.example` to an ignored local env file and update the `op://`
references to the fields in your item:

```bash
cp .env.1password.example .env.1password.local
```

Then run commands through 1Password without exposing secret values:

```bash
op run --env-file .env.1password.local -- npm run doctor:app
op run --env-file .env.1password.local -- npm start
```

## Policy

This adapter uses a local JSON policy file to map a GitHub installation and
repository to a familiar route. Start with:

```bash
cp config/example-policy.json coven-github-policy.json
```

Then replace:

- `123456` with the GitHub App installation ID.
- `987654321` with the repository ID.
- `bot_usernames` with the GitHub App bot login, for example
  `coven-cody[bot]`.
- `trigger_labels` with labels that should start tasks.
- `familiar` with the familiar id, display name, model, and skills to pass to
  `coven-code`.

Point the service at the file:

```bash
export COVEN_GITHUB_POLICY_PATH="$PWD/coven-github-policy.json"
```

Keep `publication.mode` as `record_only` for first smoke runs. Switch it to
`comment` only after you have verified the App installation, `coven-code`
runtime, Codex token, and workspace permissions.

## Runtime Checklist

```bash
npm ci
npm run build

export GITHUB_APP_ID="123456"
export GITHUB_WEBHOOK_SECRET="replace-with-github-secret"
export GITHUB_APP_PRIVATE_KEY_PATH="$PWD/keys/coven-github.private-key.pem"
export COVEN_GITHUB_POLICY_PATH="$PWD/coven-github-policy.json"
export COVEN_GITHUB_STATE_DIR="$PWD/coven-github-state"
export COVEN_CODE_BIN="$(command -v coven-code)"

npm run doctor:app
npm start
```

In another shell:

```bash
WEBHOOK_SECRET="$GITHUB_WEBHOOK_SECRET" \
  scripts/smoke-webhook.sh http://localhost:3000/webhook
```

That proves the HTTP endpoint and HMAC signature path before any GitHub token or
runtime work is attempted.

## Local App Demo

Before creating a real GitHub App, run the self-contained demo:

```bash
npm run smoke:app
```

The demo starts the built Node server on localhost, signs an `issues.labeled`
payload with the same `sha256=` HMAC format GitHub uses, loads
`config/example-policy.json`, and prints the resulting delivery, task, session
brief, and result paths.

It runs with `COVEN_GITHUB_DEMO_MODE=1`. That mode is intentionally explicit:
it verifies the app ingress and routing path, but does not mint GitHub
installation tokens, clone repositories, run `coven-code`, or publish comments.

## Functional App Smoke

On a repository where the App is installed:

1. Copy the installation ID and repository ID into `coven-github-policy.json`.
2. Add one of the configured labels, such as `coven:fix`, to an issue.
3. Confirm a delivery record appears under `COVEN_GITHUB_STATE_DIR/deliveries`.
4. Confirm a task record appears under `COVEN_GITHUB_STATE_DIR/tasks`.
5. Inspect the attempt directory if the runtime fails before enabling comment
   publication.

This keeps the first app connection auditable: GitHub delivery, policy route,
task creation, runtime attempt, and publication are separate files.
