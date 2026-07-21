# Zoolanding Notifications Agent Workflow

Start with `README.md`, then verify the current branch and worktree before editing.

- Keep the worker generic, server-only, and scoped to the exact environment, tenant, draft, domain, published package version, notification policy, and connection.
- Never store or log email addresses, message bodies, template variables, credentials, secret metadata, provider responses, or raw connection-resolution responses.
- `dev` is local/CI only. This repository has no AWS dev stack, deployment workflow, or SAM deploy profile.
- Work test-first and run three audit/fix/retest cycles before closeout.
- Do not deploy, provision a secret, or call SMTP/AWS/provider services without explicit authorization and the Phase 8 rollout gates.
