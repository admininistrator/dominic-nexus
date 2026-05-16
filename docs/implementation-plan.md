# Dominic Nexus implementation plan

Last updated: 2026-05-07

This plan is the high-level guide for reimplementing the OpenClaw architecture
as `dominic-nexus`. The authoritative task board is `docs/tasks.json`.

## Non-negotiable constraints

- `reference-openclaw/` is read-only.
- Do not copy large implementation blocks from `reference-openclaw/`.
- Implement product code only under `dominic-nexus/`.
- Keep docs and planning updates under `docs/`.
- Preserve a local-first, consent-first security posture.
- Deny shell execution, filesystem writes, network access, provider calls,
  plugin execution, and secret reads unless an explicit policy allows them.
- Never log secret values or silent telemetry.

## Current baseline

The target project already has:

- a TypeScript pnpm monorepo scaffold;
- packages for shared, config, logging, permissions, secrets, memory, tools,
  providers, channels, plugin-sdk, and core;
- CLI app scaffold with a local interactive chat loop;
- a mock provider guarded by `provider.call` permission;
- default deny, allow-all development, and interactive approval policies;
- tests for permissions, tools, providers, memory, secrets, core session/context
  creation, and CLI chat input handling.

The current implementation is still a scaffold. It does not yet have durable
config, audit logs, durable sessions/transcripts, real provider adapters,
filesystem/web/shell tools, Gateway/RPC, web UI, plugin runtime, channels, or
release hardening.

## Reference tree comparison

The reference tree shows a broad product surface. Dominic Nexus should reuse the
architecture pattern, not the implementation or full breadth on day one.

| Reference area | Meaning in OpenClaw | Dominic Nexus direction |
| --- | --- | --- |
| `src/agents`, `src/runtime.ts`, `src/entry.ts` | Agent turn orchestration and startup | `packages/core` owns runtime context, sessions, agent runner, event bus, and lifecycle |
| `src/config` | Strict runtime config and config CLI | `packages/config` owns source config, runtime snapshot, validation, and safe writes |
| `src/logging`, `src/security` | Logging, redaction, security checks | `packages/logging`, `packages/permissions`, and future `packages/audit` enforce redaction and auditability |
| `src/secrets` | Secret references and runtime secret resolution | `packages/secrets` owns SecretRef, stores, resolver, and no-secret-logging tests |
| `src/tools`, `src/web-fetch`, `src/web-search`, `src/terminal` | Built-in tools and policy-gated execution | `packages/tools` owns registry, invocation pipeline, filesystem, web, memory, and shell tools |
| `src/memory`, `packages/memory-host-sdk`, `extensions/memory-*` | Memory host and memory plugins | `packages/memory` starts with local Markdown/daily notes, then adds optional plugin slots |
| `src/channels`, `extensions/*` channel folders | Channel adapters and routing | `packages/channels` defines contracts first; selected channel plugins come later |
| `src/plugins`, `src/plugin-sdk`, `packages/plugin-sdk` | Manifest-first plugin system and SDK | `packages/plugin-sdk` exposes narrow public contracts; runtime loading stays allowlisted |
| `extensions/` | Provider/channel/tool ecosystem | Implement extension points first, then only selected providers/channels/tools |
| `ui/` | Vite control UI | `apps/web` becomes local status, config, sessions, audit, and chat UI after Gateway exists |
| `apps/` | Native/mobile companion apps | Defer until Gateway and web contracts are stable |
| `skills/`, `.agents/skills` | Agent skill folders | Add a small skill loader with symlink-safe roots after core tools and plugins |
| `test/`, `qa/`, `security/`, `scripts/` | Test topology, QA, release/security automation | Build targeted tests first, then add boundary checks, QA scenarios, and release checks |
| `.github/`, `deploy/`, Docker files | CI and deployment | Defer until local runtime is stable and package boundaries are proven |

## Delivery strategy

Build from the center outward:

1. Lock down the current scaffold with tests.
2. Add shared primitives, strict config, redacted logging, and audit events.
3. Harden permissions, secrets, filesystem bounds, shell/network denial, and
   import boundaries.
4. Build the durable core runtime: sessions, transcripts, agent runner,
   cancellation, event bus, and context assembly.
5. Add provider and tool pipelines behind permissions and audit.
6. Add memory persistence and CLI workflows.
7. Add local Gateway/RPC, then web UI.
8. Add plugin manifests, SDK boundaries, and selected channels.
9. Add skills, optional media/MCP surfaces, QA, release, and packaging.

Do not start by cloning the reference provider/channel/plugin surface. The
important parity target is the control-plane architecture and security model.

## Phases

### Phase 0: Reference discovery and governance

Goal: keep reference learning concise and auditable.

Deliverables:

- reference architecture notes;
- security notes and trust model notes;
- feature parity checklist;
- package boundary matrix;
- task board in `docs/tasks.json`.

Rules:

- Prefer `docs/reference-tree.txt` and existing notes before reading reference
  code.
- When reference code is inspected, read the smallest relevant files and record
  confirmed facts separately from assumptions.

### Phase 1: Scaffold and baseline behavior

Goal: keep the current monorepo stable before deeper runtime work.

Deliverables:

- workspace/package scripts;
- baseline package exports;
- CLI chat loop using only `MockProvider`;
- scaffold tests;
- documented Windows commands.

### Phase 2: Shared primitives

Goal: prevent every package from inventing its own IDs, errors, events, and
JSON-safe types.

Deliverables:

- branded IDs for sessions, agents, tools, providers, channels, and plugins;
- result/error helpers;
- JSON-safe and redaction-safe values;
- domain events and deterministic test utilities.

### Phase 3: Config, logging, and audit foundation

Goal: make runtime state explicit, validated, and inspectable.

Deliverables:

- strict config schema with unknown-key rejection;
- separate source config and runtime config snapshot;
- safe config writes that never persist redacted placeholders;
- structured logger with recursive redaction;
- append-only audit sink and test sink;
- audit events for provider, tool, memory, secret, config, and permission
  decisions.

### Phase 4: Permissions, secrets, and security guardrails

Goal: enforce consent-first behavior at package boundaries.

Deliverables:

- richer permission decisions and approval prompts;
- filesystem root policy with path normalization and symlink checks;
- shell policy disabled by default with environment guardrails;
- network policy disabled by default;
- SecretRef schema and resolver;
- no-secret-logging regression tests;
- import boundary tests for core, providers, tools, plugins, and channels.

### Phase 5: Core runtime and sessions

Goal: implement the durable local agent runtime.

Deliverables:

- `RuntimeContext` as dependency container;
- stable session IDs and session metadata store;
- JSONL transcript store with write serialization;
- event bus and lifecycle events;
- agent runner for intake, context assembly, provider call, tool execution,
  response shaping, and persistence;
- cancellation and timeout handling;
- session routing and queue policy.

### Phase 6: Providers and model abstraction

Goal: keep model providers behind adapters and permission checks.

Deliverables:

- `provider/model` parser that splits on the first slash;
- provider registry with capabilities and model listing;
- permission-gated provider execution;
- mock provider retained for tests;
- one real provider adapter after secrets/audit are stable;
- optional local provider placeholder;
- fallback and cooldown model only after basic provider tests pass.

### Phase 7: Tools

Goal: make every capability callable through one audited, policy-gated path.

Deliverables:

- tool input/output schemas;
- invocation pipeline with permission checks, audit, and redaction;
- workspace-bounded read-only filesystem tool;
- explicit-approval filesystem write tool;
- explicit-approval web fetch/search tools;
- shell tool disabled by default with approval, audit, cwd/env constraints, and
  Windows-aware behavior;
- memory tools;
- tool result events.

### Phase 8: Memory

Goal: provide useful local memory without cloud dependency.

Deliverables:

- memory store interface;
- Markdown-backed `MEMORY.md`;
- daily notes under `memory/YYYY-MM-DD.md`;
- keyword search;
- permission-gated writes and audit events;
- optional plugin slot for future semantic memory.

### Phase 9: CLI

Goal: make the local runtime operable without a web UI.

Deliverables:

- command parser and slash command handling;
- `/status`, `/tools`, `/memory`, `/sessions`, `/model`, and `/help`;
- config get/set/unset commands;
- secrets list/audit commands without exposing values;
- sessions list/show/resume commands;
- security audit command;
- JSON stdout mode for automation.

### Phase 10: Local Gateway/RPC

Goal: create a local control plane after the CLI runtime is stable.

Deliverables:

- local Gateway process;
- authenticated local HTTP and WebSocket APIs;
- first-frame `connect` validation for WebSocket clients;
- event streaming;
- idempotency keys for side-effecting calls;
- daemon lifecycle commands;
- local/tailnet trust model documentation and tests.

### Phase 11: Web UI

Goal: expose a local operator UI over Gateway contracts.

Deliverables:

- Vite app under `apps/web`;
- local connection flow;
- status dashboard;
- chat/session view;
- config/settings editor;
- audit log viewer;
- tools/plugins/channels views;
- focused UI and e2e tests.

### Phase 12: Plugins and SDK

Goal: support extension without exposing core internals.

Deliverables:

- plugin manifest schema;
- metadata discovery without runtime import;
- narrow plugin SDK exports;
- trusted runtime loader with explicit allowlist;
- provider/tool/channel/memory capability registration;
- plugin package contract;
- import boundary tests;
- one minimal bundled example plugin.

### Phase 13: Channels

Goal: normalize inbound/outbound messaging only after runtime security exists.

Deliverables:

- channel adapter contracts;
- sender and thread identity model;
- session routing from channel messages;
- DM/group/mention policy;
- outbound delivery contract;
- `NO_REPLY` filtering and duplicate confirmation suppression;
- selected channel plugins only after secrets/network policy is stable.

### Phase 14: Skills, MCP, and optional advanced surfaces

Goal: add optional integrations without weakening core boundaries.

Deliverables:

- skill manifest and loader;
- symlink-safe skill roots;
- skill list/install CLI;
- MCP abstraction behind permissions;
- optional media, browser, document, speech, or automation surfaces as plugins.

### Phase 15: QA, release, and packaging

Goal: make the project repeatable, testable, and shippable.

Deliverables:

- test topology and targeted Vitest projects;
- architecture and import-boundary checks;
- security regression suite;
- CLI, Gateway, and web e2e tests;
- QA scenarios;
- build and package checks;
- release checklist and user docs.

## Codex workflow

For future implementation turns:

1. Read `dominic-nexus/AGENTS.md`.
2. Read this plan.
3. Read `docs/tasks.json`.
4. Pick the first `todo` task with all dependencies complete, prioritizing
   lower phase numbers and `P0` priority.
5. Inspect only the files required for that task.
6. Implement under `dominic-nexus/` only, unless the task is documentation.
7. Update task status and related docs when behavior changes.
8. Run the narrowest relevant checks. For broad changes, run:
   - `pnpm.cmd typecheck`
   - `pnpm.cmd test`

## Near-term next tasks

The task board should be followed in dependency order. The first remaining
work is:

1. finish the docs/governance tasks for feature parity, security notes, and
   package boundaries;
2. add shared IDs, result/error helpers, events, and deterministic runtime
   utilities;
3. harden config, logging, and audit;
4. integrate audit events into provider, tool, secret, memory, and permission
   paths;
5. replace any remaining allow-all CLI development behavior with explicit
   approval in interactive paths.
