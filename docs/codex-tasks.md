# Codex task board

## Completed

- Scaffold TypeScript pnpm monorepo.
- Add CLI, core, config, logging, permissions, secrets, memory, tools, providers, channels, plugin-sdk, shared.
- Pass install/typecheck/test/dev.

## Next tasks

### Task 1 — Add tests for current scaffold

Goal: lock current behavior before adding features.

Scope:
- Add unit tests for:
  - `DefaultDenyPolicy`
  - `AllowAllDevelopmentPolicy`
  - `ToolRegistry`
  - `MockProvider`
  - `EnvSecretStore`
  - `InMemoryStore`
  - `createRuntimeContext`
  - `createAgentSession`

Expected checks:
- `pnpm.cmd typecheck`
- `pnpm.cmd test`

### Task 2 — Implement CLI chat loop

Goal: make `pnpm.cmd dev` start an interactive local chat.

Scope:
- CLI reads user input from stdin.
- CLI sends messages to `MockProvider`.
- CLI prints assistant response.
- `/exit` quits.
- No external network call.

Expected checks:
- `pnpm.cmd typecheck`
- `pnpm.cmd test`
- `pnpm.cmd dev`

### Task 3 — Add approval-based policy

Goal: replace allow-all dev policy in CLI with an approval prompt for risky actions.

Scope:
- Add `InteractiveApprovalPolicy`.
- Ask before shell/network/filesystem write/secret read/provider call.
- Keep tests deterministic by abstracting prompt IO.

Expected checks:
- `pnpm.cmd typecheck`
- `pnpm.cmd test`

### Task 4 — Add audit log

Goal: every tool/provider/secret/memory operation can be audited.

Scope:
- Add `packages/audit` or add audit primitives to `core`.
- Record timestamp, sessionId, action, decision, resource.
- Never record secret values.

Expected checks:
- `pnpm.cmd typecheck`
- `pnpm.cmd test`

### Task 5 — Inspect OpenClaw runtime entry points

Goal: understand reference architecture without copying code.

Scope:
- Read only:
  - `../reference-openclaw/README.md`
  - `../reference-openclaw/VISION.md`
  - `../reference-openclaw/package.json`
  - `../reference-openclaw/openclaw.mjs`
  - `../reference-openclaw/src/entry.ts`
  - `../reference-openclaw/src/runtime.ts`
- Write findings to `docs/reference-runtime-notes.md`.
- Do not modify `reference-openclaw`.

Expected checks:
- no code changes required