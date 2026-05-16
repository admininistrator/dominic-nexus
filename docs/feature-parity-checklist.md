# Dominic Nexus feature parity checklist

Last updated: 2026-05-07

This checklist tracks architectural parity with OpenClaw for the Dominic Nexus
reimplementation. It is not a source-code parity target. Dominic Nexus should
reuse the useful architecture patterns while keeping a smaller, private,
local-first, deny-by-default product surface.

## Status meanings

- `required`: needed for the core Dominic Nexus architecture.
- `selected`: implement a narrow version after the core security/runtime path is
  stable.
- `deferred`: intentionally postpone until there is concrete product pressure.
- `out-of-scope`: do not reimplement unless the product direction changes.

## Guiding decisions

- Reimplement architecture patterns, not OpenClaw implementation code.
- Build core security and runtime boundaries before providers, channels, media,
  or broad plugin surfaces.
- Keep provider calls, network, shell, filesystem writes, secret reads, and
  plugin execution permission-gated and audited.
- Keep external integrations opt-in, disabled by default, and backed by
  explicit SecretRef handling where credentials are needed.
- Do not try to match the full OpenClaw extension catalog, bundled skills,
  mobile apps, CI matrix, release machinery, or deployment targets early.

## Core architecture

| Area | Reference signal | Target location | Status | Notes |
| --- | --- | --- | --- | --- |
| Runtime context | `src/runtime.ts`, `src/agents`, `src/chat`, `src/context-engine` | `packages/core` | `required` | RuntimeContext should own explicit dependencies for config, logger, policy, audit, secrets, providers, tools, memory, sessions, and events. |
| Agent turn lifecycle | `src/agents`, `src/flows`, `src/trajectory` | `packages/core` | `required` | Build AgentRunner for intake, context assembly, provider call, tool execution, response shaping, transcript writes, and audit events. |
| Session metadata | `src/sessions`, `src/routing` | `packages/core` | `required` | Store session metadata separately from transcripts; session IDs and keys are routing controls, not auth boundaries. |
| Transcript storage | `src/sessions`, tests around runtime/session behavior | `packages/core` | `required` | JSONL transcript per session with serialized writes and safe recovery from malformed lines. |
| Event stream | `src/gateway`, `src/status`, UI event tests | `packages/core`, later Gateway | `required` | Define redacted domain events before Gateway and web UI depend on them. |
| Cancellation and timeouts | Runtime/tool/provider paths | `packages/core`, `packages/tools`, `packages/providers` | `required` | Add bounded execution for provider and tool calls. |

## Config, logging, audit, and shared primitives

| Area | Reference signal | Target location | Status | Notes |
| --- | --- | --- | --- | --- |
| Shared IDs and JSON-safe types | `src/types`, `src/shared`, package SDK types | `packages/shared` | `required` | Add branded IDs, Result/AppError, events, Clock, and IdGenerator before larger refactors. |
| Strict config schema | `src/config`, config tests, docs/config | `packages/config` | `required` | Separate source config from runtime snapshot; reject unknown keys and malformed values. |
| Safe config writes | Config CLI behavior and validation notes | `packages/config`, `apps/cli` | `required` | Never write redacted placeholders; require filesystem.write permission for mutations. |
| Structured logging | `src/logging`, `src/logger.ts` | `packages/logging` | `required` | Add recursive redaction and no-secret-logging regression tests. |
| Audit log | Security docs and tool/provider/runtime paths | `packages/audit` or `packages/core` | `required` | Append-only events for permission, provider, tool, memory, secret, config, session, and plugin decisions. |
| Security audit command | `src/security`, CLI security audit docs | `apps/cli`, later Gateway/UI | `selected` | Implement after config, secrets, tool policy, and audit are stable. |

## Permissions, secrets, and security

| Area | Reference signal | Target location | Status | Notes |
| --- | --- | --- | --- | --- |
| Permission decision model | `src/security`, tool policy, exec approvals | `packages/permissions` | `required` | Represent allow, deny, approval-required, policy source, and safe metadata. |
| Interactive approvals | Exec approval docs, CLI interaction paths | `packages/permissions`, `apps/cli` | `required` | Use deterministic prompt adapters for tests. |
| Filesystem root policy | File utilities, sandbox/path guardrails | `packages/permissions`, `packages/tools` | `required` | Normalize paths, reject traversal, and guard symlink escapes. |
| Shell policy | `src/terminal`, exec tool, sandbox docs | `packages/permissions`, `packages/tools` | `required` | Disabled by default; approval binds exact command/cwd/env/timeout. |
| Network policy | web fetch/search and proxy docs | `packages/permissions`, `packages/tools` | `required` | Disabled by default; every external request needs permission and audit. |
| SecretRef and stores | `src/secrets`, credential docs | `packages/secrets` | `required` | Resolve active secrets into runtime snapshots; never log resolved values. |
| Import boundary checks | Reference boundary tests and scripts | `tests` or package tests | `required` | Protect core/provider/channel/plugin SDK boundaries from bypass imports. |
| Host sandbox/runtime isolation | Sandbox docs, Docker/node-host paths | Future tools/runtime | `deferred` | Use policy guardrails first; do not copy broad sandbox machinery early. |

## Providers and models

| Area | Reference signal | Target location | Status | Notes |
| --- | --- | --- | --- | --- |
| ModelRef parsing | Model/provider docs | `packages/providers` | `required` | Parse `provider/model` by the first slash. |
| Provider registry | `extensions/*` providers, model catalog | `packages/providers` | `required` | Registry should list providers, capabilities, models, and safe errors. |
| Permission-gated provider execution | Provider runtime and auth docs | `packages/providers`, `packages/core` | `required` | AgentRunner should call providers through the centralized audited path. |
| Mock provider | Current scaffold | `packages/providers` | `required` | Keep for deterministic tests and offline CLI behavior. |
| First real provider adapter | `extensions/openai`, `extensions/anthropic`, etc. | `packages/providers` or plugin | `selected` | Add only after config, secrets, network policy, and audit are stable; use mocked transport in tests. |
| Local provider placeholder | `extensions/ollama`, `extensions/lmstudio`, local runtimes | `packages/providers` or plugin | `selected` | Optional, disabled by default, no automatic service startup. |
| Broad provider catalog | Many provider extension folders | Plugins/extensions | `deferred` | Do not recreate the reference provider catalog early. |
| Fallback/cooldown logic | Model failover notes | `packages/providers`, `packages/core` | `deferred` | Add after basic real provider behavior is proven. |

## Tools

| Area | Reference signal | Target location | Status | Notes |
| --- | --- | --- | --- | --- |
| Tool registry | `src/tools`, tool docs | `packages/tools` | `required` | All tool calls must pass through one registry/pipeline. |
| Tool schemas | Tool definitions and provider tool schemas | `packages/tools` | `required` | Validate inputs before handler execution and keep outputs JSON-safe. |
| Tool invocation pipeline | Agent/tool runtime paths | `packages/tools`, `packages/core` | `required` | Mandatory permission checks, audit, redaction, and timeout handling. |
| Read-only filesystem tool | Filesystem tools | `packages/tools` | `required` | Workspace-bounded, size-limited, and safe for binary/large files. |
| Filesystem write tool | File edit/write tools | `packages/tools` | `selected` | Requires explicit approval and root bounds. |
| Web fetch tool | `src/web-fetch`, web docs | `packages/tools` | `selected` | Requires network permission, mocked transport tests, response limits. |
| Web search tool | `src/web-search`, search providers | `packages/tools` or plugin | `selected` | Optional adapter; no default live provider. |
| Shell tool | `src/terminal`, exec docs | `packages/tools` | `selected` | Disabled by default; strict approval, audit, cwd/env/output limits. |
| Browser/automation tools | `extensions/browser`, automation docs | Plugins | `deferred` | Only after shell/network policy and plugin runtime are mature. |
| Media/document tools | media/document extension folders | Plugins | `deferred` | Model as optional plugin capability slots, not core requirements. |

## Memory

| Area | Reference signal | Target location | Status | Notes |
| --- | --- | --- | --- | --- |
| Memory abstraction | `src/memory`, `packages/memory-host-sdk` | `packages/memory` | `required` | Keep current InMemoryStore for tests; define durable store contracts. |
| Markdown memory | Memory docs and plain Markdown model | `packages/memory` | `required` | Use local `MEMORY.md`, permission-gated writes, audit events. |
| Daily notes | `memory/YYYY-MM-DD.md` reference pattern | `packages/memory` | `selected` | Add after Markdown memory is stable. |
| Keyword search | Memory tools/search | `packages/memory` | `selected` | Enough for initial local-first memory; no vector dependency required. |
| Semantic/vector memory | `extensions/memory-lancedb`, memory plugins | Plugin slot | `deferred` | Optional later, behind explicit plugin enablement. |
| Memory plugin exclusivity | Reference memory plugin slot | `packages/plugin-sdk`, `packages/memory` | `deferred` | Add when plugin runtime exists. |

## CLI and local operation

| Area | Reference signal | Target location | Status | Notes |
| --- | --- | --- | --- | --- |
| Local chat loop | `src/cli`, `src/chat` | `apps/cli` | `required` | Already scaffolded with MockProvider and `/exit`; next move through AgentRunner. |
| Slash commands | CLI/chat command docs | `apps/cli`, `packages/core` | `required` | `/status`, `/tools`, `/memory`, `/sessions`, `/model`, `/help`; handled outside the model. |
| Config commands | Config CLI behavior | `apps/cli`, `packages/config` | `selected` | get/set/unset/validate/path with safe writes. |
| Secrets commands | Secrets CLI behavior | `apps/cli`, `packages/secrets` | `selected` | List/check/audit metadata only; never print values. |
| Sessions commands | Sessions CLI behavior | `apps/cli`, `packages/core` | `selected` | list/show/resume/transcript path. |
| JSON stdout mode | `cli-json-stdout.e2e.test.ts` | `apps/cli` | `selected` | Needed for automation after core commands exist. |
| Full OpenClaw CLI command surface | Gateway, nodes, cron, hooks, MCP, pairing, doctor | `apps/cli` | `deferred` | Add only commands justified by Dominic Nexus use cases. |

## Gateway, RPC, and UI

| Area | Reference signal | Target location | Status | Notes |
| --- | --- | --- | --- | --- |
| Local Gateway protocol | `src/gateway`, protocol docs | `packages/core`, future app/package | `selected` | Define after CLI AgentRunner works; local control plane and policy boundary. |
| HTTP API | Gateway server paths | future Gateway package/app | `selected` | Authenticated local API for status, sessions, config, and chat. |
| WebSocket event stream | Gateway protocol tests | future Gateway package/app | `selected` | First frame must be `connect`; stream redacted events. |
| Daemon lifecycle | `src/daemon`, CLI gateway commands | `apps/cli`, future Gateway | `deferred` | Add after local Gateway is stable. |
| Web UI | `ui/` Vite app | `apps/web` | `selected` | Status, chat/sessions, config, audit, tools/plugins/channels. |
| Native/mobile apps | `apps/macos`, `apps/ios`, `apps/android`, `apps/swabble` | none initially | `out-of-scope` | Do not reimplement until the local Gateway/web UI product needs them. |

## Plugins, channels, and skills

| Area | Reference signal | Target location | Status | Notes |
| --- | --- | --- | --- | --- |
| Plugin manifest schema | `src/plugins`, `packages/plugin-sdk`, extension manifests | `packages/plugin-sdk` | `selected` | Manifest-first metadata before runtime import. |
| Plugin metadata discovery | Plugin docs and boundary checks | `packages/plugin-sdk`, future loader | `selected` | Root-bounded, read-only, no runtime import during discovery. |
| Narrow plugin SDK | `packages/plugin-sdk`, SDK subpath checks | `packages/plugin-sdk` | `selected` | Expose stable contracts, not core internals. |
| Trusted plugin loader | `src/plugins`, extension activation | future core/plugin loader | `selected` | Explicit allowlist, audit, and trusted-code documentation. |
| Broad extension catalog | `extensions/` provider/channel/tool ecosystem | plugins | `deferred` | Implement selected capabilities only. |
| Channel contracts | `src/channels`, channel extension folders | `packages/channels` | `selected` | Normalize sender, thread, account, room, inbound/outbound messages. |
| Channel access policy | Channel docs and routing | `packages/channels`, `packages/core` | `selected` | DM allowlists, group mention by default, context visibility separated from trigger auth. |
| External channel plugins | Slack, Discord, Telegram, WhatsApp, etc. | plugins | `deferred` | Add one selected channel only after secrets/network/routing are hardened. |
| Skill loader | `skills/`, `.agents/skills` | future skill package/module | `selected` | Local skill metadata and symlink-safe roots. |
| Bundled skill catalog | Many reference skill folders | none initially | `deferred` | Add only small local skills when needed. |
| MCP integrations | `src/mcp`, CLI/gateway surfaces | plugin/capability slot | `deferred` | Optional and permission-gated. |

## Tests, QA, release, and deployment

| Area | Reference signal | Target location | Status | Notes |
| --- | --- | --- | --- | --- |
| Unit tests | Package and root Vitest tests | package-local tests | `required` | Current scaffold has initial coverage; expand with every core package change. |
| Security regression tests | `security/`, boundary/security tests | `tests` or package tests | `required` | Cover denials, redaction, path bounds, no telemetry defaults, and secret handling. |
| Import boundary tests | Reference boundary tests/scripts | `tests` or scripts | `required` | Prevent direct imports that bypass providers/tools/config/logging boundaries. |
| CLI e2e tests | CLI e2e tests | `apps/cli` tests | `selected` | Add after AgentRunner, sessions, config, and JSON stdout exist. |
| Gateway/web e2e tests | Gateway and UI tests | Gateway and `apps/web` tests | `selected` | Add after local Gateway and UI exist. |
| QA scenarios | `qa/` scenarios | `docs/qa-scenarios.md` and optional tests | `selected` | Focus local-first flows; keep live provider/channel scenarios opt-in. |
| Release checklist | Release scripts/tests | `docs/` and package scripts | `selected` | Build/typecheck/test/security/package checks without deployment secrets. |
| Full CI/release automation | `.github`, large scripts, appcast, publish scripts | none initially | `deferred` | Avoid copying large release machinery before local runtime is stable. |
| Docker/deployment targets | Dockerfile, deploy/fly/render files | optional future packaging | `deferred` | Only if local-first deployment requirements justify it. |
| Mobile/native release | native apps and signing scripts | none initially | `out-of-scope` | Not part of current Dominic Nexus reimplementation. |

## Initial required parity target

The first meaningful parity milestone is not provider/channel breadth. It is a
working local runtime with:

- strict config;
- redacted logging;
- append-only audit;
- explicit permission decisions and approvals;
- SecretRef handling;
- durable sessions and transcripts;
- AgentRunner-based CLI chat;
- provider and tool calls through audited policy gates;
- local Markdown memory;
- import boundary tests.

After that milestone, selected parity can expand to a local Gateway, web UI,
plugin manifests, selected providers, selected tools, and selected channels.
