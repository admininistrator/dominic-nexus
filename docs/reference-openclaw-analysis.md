# OpenClaw Reference Analysis for Dominic Nexus

This handoff summarizes the OpenClaw reference design so Codex can reimplement a
different, private, local-first assistant inside `./dominic-nexus` without
copying OpenClaw implementation code.

## Review Scope

Read-only reference files inspected:

- `reference-openclaw/README.md`, `VISION.md`, `SECURITY.md`, `AGENTS.md`
- `reference-openclaw/package.json`, `pnpm-workspace.yaml`, `ui/package.json`
- scoped guides under `src/agents`, `src/gateway`, `src/plugins`,
  `src/plugin-sdk`, `src/channels`, `src/gateway/protocol`, `src/agents/tools`
- docs for architecture, agent loop, agent runtime, sessions, models,
  model failover, memory, configuration, sandboxing, secrets, security, plugins,
  skills, exec approvals, exec tool, slash commands, and network proxy
- selected contract/entry files: `openclaw.mjs`, `src/entry.ts`,
  `src/runtime.ts`, `src/index.ts`, `src/config/types.openclaw.ts`,
  `src/config/config.ts`, `src/channels/plugins/types.*.ts`,
  `src/plugins/types.ts`, `src/plugin-sdk/plugin-entry.ts`,
  `src/plugin-sdk/provider-entry.ts`, `src/gateway/protocol/*`,
  memory host SDK exports

No files under `reference-openclaw/` were modified.

## 1. Architecture Overview

OpenClaw is a TypeScript ESM monorepo centered on a long-lived local Gateway.
The Gateway owns control-plane APIs, channel connections, session state, agent
turn orchestration, plugin/runtime activation, tool policy, secrets resolution,
and event streaming.

The main product model is:

- one local-first personal assistant runtime;
- one trusted operator boundary per Gateway;
- many channels, tools, providers, plugins, sessions, and optional nodes;
- explicit routing and security controls around untrusted inbound content;
- optional companion UI/native apps around the same Gateway control plane.

The most important design idea to reuse is the separation of concerns:

- Gateway = control plane and policy boundary.
- Agent runtime = prompt/model/tool loop.
- Provider adapters = model/auth/catalog/runtime behavior.
- Tool registry = callable capabilities plus policy gates.
- Channel adapters = inbound/outbound messaging and sender identity.
- Plugin system = extension boundary with manifest-first metadata.
- Secrets layer = one resolved runtime snapshot, no hot-path secret lookups.
- Session store = durable routing metadata and transcript persistence.

Dominic Nexus should keep this shape but use stricter defaults: deny shell,
network, filesystem writes, provider calls, and secret reads unless explicitly
approved.

## 2. Package and Module Map

Reference structure:

- `src/`: core Gateway, agent runtime, CLI, config, channels, plugins, tools,
  sessions, secrets, memory, security, logging, MCP, media, web fetch/search.
- `ui/`: Vite/Lit control UI with Vitest.
- `apps/`: macOS, iOS, Android, shared native app code, optional node surfaces.
- `extensions/`: provider/channel/tool/memory/plugin ecosystem.
- `packages/`: reusable SDK packages such as `sdk`, `plugin-sdk`,
  `memory-host-sdk`, `plugin-package-contract`.
- `skills/`: bundled AgentSkills-compatible skill folders.
- `docs/`: public architecture, setup, security, CLI, and plugin docs.
- `test/`: Vitest project configs, fixtures, helpers, e2e and boundary tests.
- `scripts/`: build, release, validation, protocol generation, plugin checks.
- `security/`: static/security rule support.

Target mapping for `dominic-nexus`:

- `packages/core`: Gateway/session/agent-loop orchestration.
- `packages/config`: strict config schema, defaults, safe load/write.
- `packages/logging`: structured logs plus redaction.
- `packages/permissions`: policy engine and approval decisions.
- `packages/secrets`: SecretRef and secret stores.
- `packages/tools`: tool definitions, registry, invocation pipeline.
- `packages/providers`: model/provider abstraction.
- `packages/channels`: minimal channel contract.
- `packages/memory`: markdown/file-backed memory abstraction.
- `packages/plugin-sdk`: public extension contract.
- `packages/shared`: ids, result types, events, common utilities.
- `apps/cli`: local CLI and initial chat loop.
- `apps/web`: later local control UI.

## 3. Core Abstractions and Responsibilities

Use these abstractions in Dominic Nexus:

- `RuntimeContext`: dependency container for config, logger, permissions,
  secrets, providers, tools, memory, sessions, and audit sink.
- `AgentSession`: one conversation lane with session id, agent id, model state,
  runtime state, and transcript path.
- `AgentRunner`: serialized agent turn lifecycle: intake, context assembly,
  provider call, tool execution, final response, persistence.
- `ToolRegistry`: registers tool metadata and handlers; all tool calls must pass
  permission checks before execution.
- `ProviderRegistry`: resolves `provider/model` refs, auth, model capabilities,
  and provider call behavior.
- `PermissionPolicy`: returns allow, deny, or approval-required for every
  sensitive action.
- `SecretResolver`: resolves SecretRefs into a runtime snapshot and never logs
  resolved values.
- `MemoryStore`: reads/writes durable memory through explicit interfaces.
- `ChannelAdapter`: normalizes inbound sender/channel identity and handles
  outbound replies.
- `PluginManifest` and `PluginApi`: future extension boundary; metadata first,
  runtime activation second.
- `AuditLog`: append-only record of action, actor/session, decision, resource,
  and timestamp without secrets.

## 4. Runtime Flow

Reference flow:

1. CLI launcher checks Node/runtime, normalizes env/argv, then loads CLI.
2. CLI command starts Gateway, sends a Gateway RPC, or runs a local command.
3. Gateway startup loads config, validates schemas, resolves active secrets,
   builds plugin metadata, starts HTTP/WS surfaces, starts enabled channels and
   background services.
4. Inbound channel message is normalized into sender, channel, account, room,
   thread, and message metadata.
5. Access policy checks DM/group policy, allowlists, mentions, owner commands,
   and context visibility.
6. Session router chooses session key/id and queue mode.
7. Agent turn resolves model, auth profile, runtime, skills, bootstrap context,
   memory context, tool inventory, and prompt.
8. Provider/runtime executes the model turn.
9. Tool calls pass tool policy, sandbox/host routing, exec approvals, and
   plugin hooks.
10. Assistant/tool/lifecycle events stream back through Gateway.
11. Final response is shaped, duplicate messaging-tool confirmations are
   suppressed, `NO_REPLY` is filtered, transcript/session metadata is persisted,
   and outbound channel delivery occurs.

Dominic Nexus initial flow should be simpler:

1. CLI starts local runtime.
2. CLI reads a user message.
3. Runtime creates or loads one session.
4. Permission policy checks provider call.
5. Mock provider replies.
6. Transcript/audit entries are written.
7. CLI prints response.

Then add tools, memory, approvals, and channels incrementally.

## 5. Configuration System

Reference behavior:

- Config is JSON5 at `~/.openclaw/openclaw.json`, with env override for path.
- Strict schema validation rejects unknown/malformed config.
- Runtime config is a resolved snapshot, separate from source config for writes.
- Includes and env substitution happen before runtime defaults.
- Hot reload keeps the last accepted runtime config if a new candidate fails.
- Last-known-good config exists, but startup does not silently restore it.
- Plugin and channel schemas can extend validation metadata.
- Config CLI supports get/set/unset, strict JSON, merge/replace protections.

Dominic Nexus recommendation:

- Use `nexus.config.json` or `~/.dominic-nexus/config.json` later, but start
  with an explicit config path in tests.
- Prefer `zod` or TypeBox for schema plus inferred TypeScript types.
- Fail closed on unknown keys.
- Keep `SourceConfig` separate from `RuntimeConfig`.
- Add defaults through pure functions.
- Never write redacted placeholders back to config.
- Add tests for malformed config, unknown keys, SecretRef activation, merge
  safety, and no secret logging.

## 6. Tool and Plugin System

Reference tool model:

- Tool policy and sandbox policy are separate.
- `deny` wins; explicit `allow` narrows the callable set.
- Tool groups exist for runtime, filesystem, sessions, memory, web, UI,
  automation, messaging, nodes, agents, media, and OpenClaw-owned tools.
- `exec` can route to sandbox, gateway host, or node host.
- Host exec approvals are a guardrail, not a multi-tenant auth boundary.
- Elevated mode is exec-only and bypasses sandbox routing when explicitly
  allowed.

Reference plugin model:

- Plugins are trusted in-process code once installed/enabled.
- Native plugins use `openclaw.plugin.json` for manifest-first metadata.
- Bundle-style plugins can map external bundle formats into skills/config.
- Discovery/config/setup should work from manifest metadata before plugin
  runtime executes.
- Runtime loading registers capabilities into a registry.
- Capabilities include providers, CLI backends, channels, tools, commands,
  hooks, services, gateway methods, speech, media, web search/fetch, and memory.
- Public SDK uses narrow subpaths instead of broad internal imports.
- Memory is an exclusive plugin slot.

Dominic Nexus recommendation:

- Phase 1: build only core `ToolRegistry`, no plugin runtime.
- Phase 2: add manifest parsing with `id`, `name`, `version`, `capabilities`,
  `configSchema`, and optional `skills`.
- Phase 3: add runtime plugin API with a tiny trusted API surface.
- Keep external plugins unable to import `packages/core` internals.
- Treat plugins as trusted code and document that clearly.

## 7. Provider and Model Abstraction

Reference behavior:

- Model refs are `provider/model`, split on the first `/`.
- Provider, model, agent runtime, and channel are different layers.
- Provider plugins own auth, model catalog, onboarding hints, model id
  normalization, transport compatibility, tool-schema normalization, failover
  classification, usage reporting, and thinking/reasoning profiles.
- Agent runtime can be PI, Codex, CLI backend, ACP, etc.
- Configured defaults can use fallback chains.
- Explicit user session model selections are strict and should fail visibly.
- Auth profiles can rotate within a provider before model fallback.
- Cooldowns and failover state are persisted narrowly to avoid overwriting
  unrelated session changes.

Dominic Nexus recommendation:

- Start with `MockProvider`.
- Add `ModelRef` parser with first-slash semantics.
- Add `ProviderRegistry` with `listModels`, `complete`, and `capabilities`.
- Keep provider calls behind permission checks.
- Store provider credentials only through `packages/secrets`.
- Add fallback only after basic provider tests are stable.

## 8. Memory and Storage Model

Reference behavior:

- Durable memory is plain Markdown in the agent workspace:
  `MEMORY.md`, `memory/YYYY-MM-DD.md`, optional `DREAMS.md`.
- Memory tools include search/read through the active memory plugin.
- Default memory can be SQLite-backed for search/indexing, with optional QMD,
  Honcho, LanceDB, and wiki layers.
- Session metadata and transcripts are Gateway-owned:
  `sessions.json` plus one JSONL transcript per session.
- Session store tracks `sessionStartedAt`, `lastInteractionAt`, and `updatedAt`
  separately.
- Transcript writes are protected by session write locks.

Dominic Nexus recommendation:

- Start with one workspace root and one `MEMORY.md`.
- Add `memory/YYYY-MM-DD.md` daily notes after CLI chat works.
- Store transcripts as JSONL under a configured state directory.
- Keep semantic search optional; keyword search is enough initially.
- Treat memory files as trusted local state, but require permission for writes.

## 9. Permission and Security Model

Reference trust model:

- One trusted operator boundary per Gateway.
- Not designed as hostile multi-tenant isolation.
- Authenticated Gateway callers are trusted operators.
- Session ids and session keys are routing controls, not auth boundaries.
- Channel DM/group policies gate who can trigger the agent.
- Context visibility controls supplemental quoted/thread context separately.
- Sandbox is optional; when off, tools run on host.
- Exec approvals reduce accidental execution risk.
- SecretRefs resolve eagerly into an in-memory snapshot.
- Filesystem-sensitive operations use safe helpers and explicit root bounds.
- Optional network proxy routes process-local HTTP/WebSocket egress.
- Security audit checks config, filesystem permissions, gateway exposure,
  plugin risk, tool exposure, sandbox footguns, and model hygiene.

Dominic Nexus should intentionally differ:

- Default deny for shell, write, network, provider, and secret reads.
- Provider calls should require explicit user approval until configured
  otherwise.
- Filesystem tools should default to read-only and workspace-only.
- Shell should default to disabled.
- Network should default to disabled.
- Plugins should require explicit allowlist.
- Every sensitive decision should emit an audit event.
- No telemetry unless explicitly configured by the user.

## 10. CLI Behavior

Reference CLI:

- Root binary is `openclaw`.
- Launcher handles Node version, compile cache, respawn, env normalization,
  Windows argv normalization, root version/help fast paths, and Gateway fast
  path.
- Commands include onboarding, gateway, agent, message, config, models,
  plugins, skills, secrets, security audit, sessions, logs, doctor, pairing,
  nodes, cron, hooks, MCP, and webhooks.
- Chat slash commands are handled by Gateway, not the model.
- Directives such as thinking/model/exec/queue can persist session settings
  when sent alone by authorized senders.

Dominic Nexus initial CLI should be much smaller:

- `nexus dev` or current `pnpm.cmd dev`: interactive local chat.
- `/exit`: quit.
- `/status`: print session/model/config summary.
- `/memory`: show memory file path/status.
- `/tools`: list registered tools and permission state.
- Later: `config get/set`, `secrets audit`, `security audit`, `sessions list`,
  `plugins list`, `gateway run`.

## 11. Important Edge Cases

- Gateway WS first frame must be `connect`; invalid first frames close hard.
- Side-effecting RPCs need idempotency keys to make retries safe.
- Direct loopback can have smoother pairing rules, but remote/tailnet must not
  be silently trusted.
- Shared-secret Gateway auth is full operator access in the reference.
- Config validation failure prevents startup or skips reload; do not continue
  with partially applied config.
- Unresolved SecretRefs on active surfaces fail startup/reload; inactive refs
  may warn only.
- Redacted placeholders must never be promoted to last-known-good config.
- `provider/model` parsing splits on the first slash because model ids can
  contain slashes.
- User-selected session model overrides should be strict; configured defaults
  may use fallback chains.
- Session write locks prevent transcript races across async paths/processes.
- Daily/idle session freshness should not be extended by background system
  metadata writes.
- Group chats should require mention by default.
- Trigger authorization and supplemental context visibility are different
  controls.
- Sandbox `non-main` is based on session main key, not agent id.
- Docker sandbox path mapping must use host paths when Gateway itself runs in a
  container.
- Explicit `host=sandbox` should fail closed if sandboxing is off.
- Host exec should reject env overrides that enable binary/library hijacking
  such as `PATH`, `LD_*`, or `DYLD_*`.
- Approval-backed shell runs can bind exact command/cwd/env and one direct file
  operand, but cannot semantically model every interpreter loader path.
- Plugin discovery should not eagerly import heavy runtime modules.
- Plugin metadata snapshots should be replaced, not mutated globally.
- Channel hot paths should use lightweight descriptors before loading full
  channel runtime.
- `NO_REPLY`/`no_reply` should not be sent to users as a final answer.
- Duplicate visible confirmations from messaging tools should be suppressed.
- Network proxy routing is a guardrail, not an OS-level sandbox.
- Skill roots must reject symlink escapes.
- On Windows, use `pnpm.cmd` and account for PowerShell/cmd differences.

## 12. What Not to Copy Directly

- Do not copy OpenClaw source modules or large implementation blocks.
- Do not copy OpenClaw branding, naming, jokes, mascot language, docs tone, or
  CLI names.
- Do not copy the permissive personal-assistant host-exec defaults.
- Do not reproduce the full multi-channel/provider/plugin surface early.
- Do not copy the 200+ SDK subpath model before Dominic Nexus has real plugin
  pressure.
- Do not copy provider-specific model ids or version assumptions into stable
  config defaults.
- Do not copy OpenClaw's complex release/testbox/docker/mobile app machinery.
- Do not import the reference code or keep runtime compatibility with it.
- Do not design Dominic Nexus as a shared hostile multi-tenant Gateway.
- Do not expose plugin backdoors into core internals.

## 13. Suggested Implementation Order

1. Lock the current scaffold with tests for registries, config, logging,
   permissions, secrets, memory, providers, tools, and core session creation.
2. Implement the CLI chat loop using `MockProvider`; no network.
3. Add audit events for provider calls, tool calls, secret access, memory access,
   and config writes.
4. Replace allow-all development policy with interactive approval policy.
5. Implement strict config schema and runtime config snapshot.
6. Implement SecretRef shape and env-backed secret store.
7. Implement transcript/session store with JSONL append and session metadata.
8. Implement `MEMORY.md` read/write through permission gates.
9. Add a minimal provider abstraction and one real provider adapter only after
   permissions and secrets are tested.
10. Add read-only filesystem tool, then write/edit only with explicit approval.
11. Add shell tool last, disabled by default, with approval and audit.
12. Add minimal local Gateway/RPC only after CLI runtime is stable.
13. Add web UI for status/config/audit after Gateway contracts exist.
14. Add plugin manifest parsing before runtime plugin execution.
15. Add selected channels only after session routing and permissions are
   hardened.

## 14. Files Codex Should Create or Modify

Near-term files in `dominic-nexus`:

- `packages/shared/src/`: ids, result helpers, event types, JSON-safe types.
- `packages/config/src/`: schema, defaults, loader, validation errors,
  runtime snapshot.
- `packages/logging/src/`: logger interface, redaction helpers, test logger.
- `packages/permissions/src/`: decision types, default deny policy,
  interactive approval policy, test prompt adapter.
- `packages/secrets/src/`: SecretRef type, env store, resolver, redaction tests.
- `packages/tools/src/`: tool definition, registry, invocation pipeline,
  permission integration.
- `packages/providers/src/`: model ref parser, provider interface,
  mock provider, registry.
- `packages/memory/src/`: memory store interface, markdown memory store,
  permission-gated writes.
- `packages/core/src/`: runtime context, session, agent loop, transcript store,
  audit integration.
- `packages/channels/src/`: normalized channel/sender/message contracts.
- `packages/plugin-sdk/src/`: minimal manifest and plugin API types.
- `apps/cli/src/`: interactive chat loop, command parser, status output.
- `tests/` or package-local `*.test.ts`: permission, secrets, tool/provider,
  config, memory, and session tests.
- `docs/`: keep architecture/security notes current as behavior changes.

Avoid creating broad provider/channel/plugin implementations until the core
security pipeline is tested.

## 15. Commands and Tests Codex Should Run

For Dominic Nexus after code changes:

```powershell
cd C:\Users\Admin\Documents\DominicNexusDev\dominic-nexus
pnpm.cmd typecheck
pnpm.cmd test
```

When package metadata or dependencies change:

```powershell
pnpm.cmd install
pnpm.cmd typecheck
pnpm.cmd test
```

When CLI chat behavior changes:

```powershell
pnpm.cmd dev
```

When build outputs or package boundaries change:

```powershell
pnpm.cmd build
```

Suggested targeted test areas:

- config rejects unknown keys and unsafe values;
- default policy denies shell/network/write/provider/secret access;
- approval policy can be tested with deterministic prompt IO;
- secret resolver never logs secret values;
- tool registry cannot execute without permission pipeline;
- provider registry cannot call providers directly from core bypasses;
- memory writes require permission;
- transcript writes are append-only and session-scoped;
- plugin SDK types do not expose core internals.

## Bottom Line for Dominic Nexus

Reimplement the architecture pattern, not the code. The useful OpenClaw lessons
are the control-plane/runtime split, manifest-first extension design, strict
config validation, explicit session routing, provider/runtime separation,
permission-gated tools, eager secret snapshots, and auditability. Dominic Nexus
should keep those boundaries but choose a smaller surface and stricter security
defaults from the start.
