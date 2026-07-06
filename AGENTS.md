# AGENTS.md — coven-github-webhook

Guidance for **AI agents** (Codex, Claude Code, and any Coven familiar) opening
pull requests against this repo. This is the agent-specific layer; read
[`README.md`](README.md) for what this deployment bundle is.

> **What this repo is:** the hosted webhook deployment bundle for the
> `coven-github` integration — the small always-on service that receives GitHub
> webhook events and forwards them to the Coven GitHub App backend.

## Branch & PR workflow

- **Never push to `main`.** Every change lands via a PR. Branch from current
  `origin/main`.
- **Fresh branch per task**; use a worktree if multiple sessions may touch this
  repo:
  ```sh
  git fetch origin main
  git worktree add -b <branch> /tmp/ghwebhook-<branch> origin/main
  ```
- Keep the diff scoped to one concern; conventional-commit subjects (`feat:`,
  `fix:`, `docs:`, `chore:`, `refactor:`).
- After merge: delete the remote branch, remove your local worktree/branch.

## Before opening the PR

- If you touched TypeScript, keep it runnable on the target host: avoid heavy
  runtime dependencies unless the deployment target supports them, and don't
  break the Node entrypoint.
- Smoke-test the webhook handler locally where possible (a signed sample
  payload) before relying on the hosted deploy.

## Repo-specific invariants (don't break these)

- This is a **thin hosted forwarder**, not the app logic. Familiar/authority and
  GitHub-App behavior lives in `coven-github` — don't reimplement it here.
- **Never commit webhook secrets, signing secrets, App private keys, or tokens.**
  Configuration comes from the deploy environment, not the repo.
- **Always verify the GitHub webhook signature** (`X-Hub-Signature-256`) before
  acting on a payload. Don't add code paths that skip verification.

## Attribution — credit contributors correctly

When you re-land or build on someone else's work (a fork PR, an issue author's
proposal, a co-author), **credit the human contributor with a working
GitHub-linked trailer** so they appear in the contributors graph and on their
profile:

```
Co-authored-by: Full Name <ID+username@users.noreply.github.com>
```

- Use the **numeric-id no-reply form**. Get the id with `gh api users/<login> --jq .id`.
- **Never** use a machine or `.local` email (e.g. `name@Someones-Mac.local`) in a
  co-author trailer — it links to no account and gives **zero** credit.
- When a squash-merge folds a contributor's PR into an internal branch, preserve
  their `Co-authored-by:` line in the squash commit message.
- Credit **people**, not AI tools.

## Secrets & safety

- Never commit secrets, tokens, or private emails. Use `*.noreply.github.com`
  for attribution.
- Don't weaken signature verification or deployment safeguards to land a change;
  surface the blocker instead.

## Claude Code

`CLAUDE.md` points here — this file is the source of truth for both.
