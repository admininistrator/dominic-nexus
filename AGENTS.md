# AGENTS.md

## Project

`dominic-nexus` is the implementation target.

This is a private, local-first AI assistant inspired by OpenClaw's architecture, but implemented as an independent codebase.

## Allowed changes

Codex may create, modify, and delete files inside this directory unless a task says otherwise.

## Reference policy

The reference project is at `../reference-openclaw/`.

Use it only for:

- architecture comparison
- API/interface discovery
- behavior understanding
- test strategy inspiration

Do not copy large implementation blocks.

## Architecture principles

Core boundaries:

- `apps/`: user-facing applications
- `packages/core/`: runtime and orchestration
- `packages/config/`: config schema and loading
- `packages/logging/`: structured logs
- `packages/permissions/`: tool execution policy
- `packages/secrets/`: secret references and secret loading
- `packages/memory/`: memory abstraction
- `packages/tools/`: built-in tools
- `packages/channels/`: chat/channel adapters
- `packages/providers/`: model/provider adapters
- `packages/plugin-sdk/`: plugin authoring API
- `packages/shared/`: shared types/utilities

## Security requirements

- No secret values in logs.
- No implicit network calls from core runtime.
- No implicit shell execution.
- All tools must declare permission requirements.
- All external providers must be behind adapters.
- All filesystem tools must support allow/deny policies.
- Plugin code must not import internal runtime modules unless explicitly allowed.

## Testing requirements

For each package:

- unit tests for pure logic
- boundary tests for import rules
- security tests for permission checks
- smoke tests for app entry points

## Preferred package manager

Use `pnpm` unless the repository later standardizes on something else.

## Before implementing

For each non-trivial task:

1. Read relevant docs in `../docs/`.
2. State which reference files are relevant.
3. Inspect only necessary files.
4. Implement a small change.
5. Run the narrowest relevant test.
6. Summarize changed files and risks.