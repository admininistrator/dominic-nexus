# AGENTS.md

## Project

`dominic-nexus` is the implementation target for a private, local-first AI assistant inspired by OpenClaw.

`../reference-openclaw/` is a read-only reference implementation.

---

## Hard rules

- Do not modify `../reference-openclaw/`.
- Do not copy large implementation blocks from `../reference-openclaw/`.
- Implement new code only inside `dominic-nexus/`.
- Prefer small, reviewable changes.
- Do not commit `node_modules/`, build outputs, caches, secrets, or generated artifacts.
- After every code change, run the narrowest relevant check.
- For broad changes, run:
  - `pnpm.cmd typecheck`
  - `pnpm.cmd test`

---

## Windows commands

Use `pnpm.cmd` on Windows PowerShell.

Common commands:

```powershell
pnpm.cmd install
pnpm.cmd typecheck
pnpm.cmd test
pnpm.cmd dev
pnpm.cmd build
```

---

## Architecture boundaries

Current packages:

- `packages/shared`: common types and utilities
- `packages/config`: config loading and validation
- `packages/logging`: structured logging
- `packages/permissions`: permission decisions and policy engine
- `packages/secrets`: secret references and secret stores
- `packages/memory`: memory abstraction
- `packages/tools`: tool definitions and tool registry
- `packages/providers`: model provider abstraction
- `packages/channels`: inbound/outbound channel abstraction
- `packages/plugin-sdk`: public plugin API
- `packages/core`: runtime orchestration
- `apps/cli`: CLI application

---

## Security rules

- Default behavior should be deny-by-default.
- Never log secret values.
- Shell execution must require explicit permission.
- Filesystem write must require explicit permission.
- Network requests must require explicit permission.
- Provider calls must go through `packages/providers`.
- Tool execution must go through `packages/tools`.
- Config must go through `packages/config`.
- Logging must go through `packages/logging`.

---

## Reference inspection rules

Before inspecting `../reference-openclaw/`, prefer reading local docs in `../docs/`.

When inspecting reference code:

- Inspect only files relevant to the current task.
- Prefer README, package.json, public exports, and index files first.
- Do not recursively inspect huge directories.
- Summarize findings into `../docs/`.
- Separate confirmed facts from assumptions.

Avoid reading these paths unless explicitly needed:

- `../reference-openclaw/pnpm-lock.yaml`
- `../reference-openclaw/scripts/`
- `../reference-openclaw/test/`
- `../reference-openclaw/qa/`
- `../reference-openclaw/.github/`
- `../reference-openclaw/docs/images/`
- `../reference-openclaw/docs/.generated/`
- all `node_modules/`
- all `dist/`
- all `build/`
- all `coverage/`

---

## Review checklist

Before finishing a task, report:

- Files changed
- Tests/checks run
- Remaining risks
- Suggested next task