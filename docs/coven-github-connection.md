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

The adapter can route these GitHub App webhook events:

- `issues`
- `issue_comment`
- `pull_request`
- `pull_request_review`
- `pull_request_review_comment`
- `check_suite`
- `check_run`
- `push`

For every route using `publication.mode: comment`, the installed GitHub App must
subscribe to both **Pull request** (`pull_request`) and **Push** (`push`) events.
The route's `enabled_triggers` must contain all four safety triggers:

- `pull_request.synchronize` for new commits or force-pushes on the PR head.
- `pull_request.edited` for base-branch retargeting.
- `pull_request.reopened` to reconcile a PR when it becomes active again.
- `push` to reconcile open PRs when new commits land on their base branch. Push
  deliveries have no `action`, so the policy key is exactly `push`, not `push.`.

These deliveries let the adapter dismiss signed, decisive covencat reviews
whose reviewed head/base pair is no longer current. Native publication fails
closed if any required policy trigger is absent. `doctor:app` reports each
missing trigger as an error. Keep the route on `record_only` until both the
policy and App subscriptions are complete. After checking the live App settings,
set `COVEN_GITHUB_REVOCATION_EVENTS=pull-request-and-push-verified`; this explicit
deployment declaration is also required for native PR publication.

Treat the manifest file and the live App registration as separate checks:
ensure `docs/app-manifest.json` in `OpenCoven/coven-github` lists both events,
then verify the installed App's settings also subscribe to **Pull request** and
**Push**. Updating a manifest file does not retroactively update an existing
GitHub App registration.

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
- `enabled_triggers` with the exact event/action pairs allowed to spend compute,
  plus actionless `push` where needed. Events not listed are acknowledged and
  ignored. A `publication.mode: comment` route must include all four
  native-review safety triggers listed above; otherwise publication fails
  closed.
- `familiar` with the familiar id, display name, model, and skills to pass to
  `coven-code`.

Point the service at the file:

```bash
export COVEN_GITHUB_POLICY_PATH="$PWD/coven-github-policy.json"
```

Keep `publication.mode` as `record_only` for first smoke runs. Switch it to
`comment` only after you have verified the App installation, `coven-code`
runtime, Codex token, workspace permissions, both required GitHub App webhook
subscriptions, and all four required safety triggers.

`record_only` controls publication, not process isolation. Non-demo work stays
blocked until the mandatory runtime sandbox below passes its executable probe.
For decisive native reviews, also configure a bounded list of trusted
validation commands under `publication.validation_commands`; a runtime-authored
claim without a matching successful sandbox receipt is published as COMMENT.
The adapter replaces model-authored `tests_run` claims with signed host receipts;
file reads, searches, PR text, and model narratives are never execution proof.

Autoreview and branch repair are independent repository opt-ins. Configure
`autoreview.enabled` for exact-SHA reviews and optionally `include_drafts`.
Configure `repair.enabled` only for trusted same-repository branches, with
`max_attempts` from 1 through 10, bounded `allowed_paths`, `protected_paths`,
`protected_branches`, `max_changed_files`, and `max_diff_bytes`. Repair sessions
receive file tools only; the host performs validation, commit, and non-force push
with a fresh repository-scoped installation token. Set `kill_switch` at the
repository route to stop both new tasks and any in-progress repair before push.
The GitHub App installation must grant repository Contents read/write for repair;
the adapter requests that authority only in the fresh repair token and does not
reuse the publication or runtime token.

## Runtime Checklist

```bash
npm ci
npm run build

export GITHUB_APP_ID="123456"
export GITHUB_WEBHOOK_SECRET="replace-with-github-secret"
export GITHUB_APP_PRIVATE_KEY_PATH="$PWD/keys/coven-github.private-key.pem"
export COVEN_GITHUB_POLICY_PATH="$PWD/coven-github-policy.json"
export COVEN_GITHUB_STATE_DIR="$PWD/coven-github-state"
install -d -m 700 "$COVEN_GITHUB_STATE_DIR"
export COVEN_RUNTIME_ISOLATION="bwrap"
export COVEN_RUNTIME_EXTERNAL_ISOLATION="network-egress-and-resource-limits-verified"
export COVEN_GITHUB_REVOCATION_EVENTS="pull-request-and-push-verified"
export COVEN_BWRAP_BIN="/usr/bin/bwrap"
export COVEN_RUNTIME_ROOTFS="/opt/coven-runtime/rootfs"
export COVEN_CODE_BIN="/usr/local/bin/coven-code" # path inside the rootfs
export COVEN_RUNTIME_NETWORK="shared"             # explicit Codex egress opt-in

npm run doctor:app
npm start
```

Build the dedicated rootfs as an administrator-controlled deployment artifact.
It must contain the configured `coven-code`, `/usr/bin/git`, `/bin/sh`,
`/bin/true`, their libraries, CA/DNS files, and required runtime assets. Do not
copy the webhook checkout, state directory, policy, App key, hosting-user home,
or `.coven-code` token store into it. Bubblewrap must be able to create user
namespaces on the target host; `doctor:app` runs a real read/write isolation
probe and fails when it cannot.

The external-isolation declaration is intentionally mandatory. Set it only
after the worker host or container enforces allowlisted egress (including no
loopback, LAN, or metadata access) and CPU, memory, PID, workspace/disk, and
scratch limits. Bubblewrap mount namespaces and timeouts do not provide those
controls. A state directory from an older deployment must be owned by the
service user and made inaccessible to group/other (for example, `chmod -R go-rwx
"$COVEN_GITHUB_STATE_DIR"`) before this version starts.

The checked-in [`deploy/Containerfile`](../deploy/Containerfile) is the
reference production boundary. It resolves the fixed GitHub and Codex endpoint
allowlist while building the immutable image, installs those addresses into
both the service and sandbox root filesystems, and applies a default-deny nft
output policy before dropping all capabilities. DNS, loopback, LAN, metadata,
IPv6, and non-HTTPS egress remain blocked; the only private-address exception is
the container's fixed self-address on the webhook listener port, which rootless
Podman uses to deliver ingress. The example user service additionally
sets cgroup memory, CPU, PID, file-descriptor, process, tmpfs, and read-only
root-filesystem limits. Mount `COVEN_GITHUB_STATE_DIR` from a dedicated,
persistent filesystem no larger than 8 GiB; the entrypoint measures the backing
filesystem and refuses startup above `COVEN_STATE_FILESYSTEM_MAX_BYTES`. Build
input `deploy/artifacts/coven-code` must be the tested binary for the recorded
Coven Code revision; the directory is ignored by git and must never contain
credentials.

Always start the resulting image by digest, retain the previous digest for
rollback, and verify the image labels, nft rules, zero effective capabilities,
allowed GitHub/Codex reachability, rejected non-allowlisted egress, health
endpoint, and signed-webhook rejection before enabling publication. If an
allowlisted service changes addresses, build and verify a new immutable image;
do not enable DNS or widen the runtime network as a shortcut.
Run `node /usr/share/coven/probe-runtime.mjs` with the production mounts and
environment to execute the same bubblewrap read/write/network probe used by a
real task before promotion.
Run `node /usr/share/coven/verify-github-app.mjs` in the same image to verify
the live installation has pull-request and push subscriptions plus the exact
Contents, Pull requests, Issues, and Metadata authority needed by review and
repair. A checked-in manifest is not evidence of the live App settings.

When public ingress and the sandbox host are separate, keep all App and model
credentials on the sandbox host. The reference ingress relay forwards raw
headers and bodies to a loopback-only reverse port and holds no secrets. Restrict
its SSH key server-side with `restrict,port-forwarding,permitopen="none"` and an
exact `permitlisten` for that one loopback port. Pin the host key, bind both ends
to loopback, and never expose the worker port directly to the LAN or Internet.
The state-volume example uses a fixed-size ext4 image through FUSE so attempts
and recovery artifacts persist while the entrypoint's 8 GiB hard check remains
meaningful.

This release passes the model credential to `coven-code`, so an untrusted
checkout can still try to consume or encode it through the allowed model
channel. Limit real execution to trusted repositories. Supporting public or
otherwise untrusted pull requests requires a separately constrained worker and
a quota-limited credential broker that does not expose a reusable model token
to repository code; the declaration above must remain unset until that boundary
is actually deployed.

Mount the Codex token directory writable only by the service account. The host
refreshes an access token within five minutes of expiry, atomically persists the
rotated OAuth record, and passes only the access token into bubblewrap. The
refresh token and account registry are never mounted into a task sandbox.

The adapter mounts only per-task input (read-only), the checkout and result
directory (writable), and the checkout `.git` directory again as read-only. It
uses an empty `/proc` in the private PID namespace, avoiding host procfs exposure
and nested procfs-mount authority. It passes no GitHub token, askpass helper,
App secret, SSH agent, or parent home to
`coven-code`. Publication authority is minted only after the sandbox exits.
Validation commands run again without credentials or network access. If the
host cannot satisfy this boundary, leave real execution disabled and use demo
mode or an externally isolated worker; there is no unsafe direct fallback.

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
