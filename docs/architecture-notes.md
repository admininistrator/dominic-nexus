# OpenClaw reference architecture notes

## High-level shape

The reference project appears to be a large TypeScript-first monorepo with:

- core runtime under `src/`
- web UI under `ui/`
- apps under `apps/`
- packages under `packages/`
- extensions under `extensions/`
- skills under `skills/`
- documentation under `docs/`
- release/build/test automation under `scripts/`
- QA scenarios under `qa/`
- security checks under `security/`

## Major source areas

### `src/`

Likely core runtime and built-in features.

Visible domains include:

- `agents`
- `channels`
- `chat`
- `cli`
- `commands`
- `config`
- `context-engine`
- `daemon`
- `gateway`
- `memory`
- `mcp`
- `plugin-sdk`
- `plugins`
- `routing`
- `security`
- `secrets`
- `sessions`
- `tools`
- `web-fetch`
- `web-search`

### `ui/`

Likely Vite/Vitest-based frontend app.

Visible files:

- `vite.config.ts`
- `vitest.config.ts`
- `package.json`
- `index.html`
- `src/`
- `public/`

### `extensions/`

Large provider/channel/plugin ecosystem.

Visible categories:

- model providers: `openai`, `anthropic`, `google`, `xai`, `mistral`, `qwen`, `ollama`, `lmstudio`, etc.
- channels: `telegram`, `slack`, `discord`, `whatsapp`, `signal`, `line`, `matrix`, etc.
- media: `image-generation-core`, `video-generation-core`, `speech-core`, etc.
- tools: `browser`, `firecrawl`, `brave`, `tavily`, `document-extract`, etc.
- memory: `memory-core`, `memory-lancedb`, `memory-wiki`, etc.

### `skills/`

Likely agent-facing skills or tool recipes.

Examples:

- `github`
- `slack`
- `notion`
- `obsidian`
- `weather`
- `summarize`
- `voice-call`
- `taskflow`
- `apple-notes`
- `1password`

### `packages/`

Reusable packages:

- `sdk`
- `plugin-sdk`
- `plugin-package-contract`
- `memory-host-sdk`

### `apps/`

Native/mobile/desktop apps:

- `macos`
- `ios`
- `android`
- `swabble`
- `macos-mlx-tts`

### `scripts/`

Very large automation surface including:

- build
- test
- release
- docker
- CI
- QA
- plugin publishing
- security checks
- package generation

## Initial target architecture mapping

For Dominic Nexus:

- `src/agents` -> `packages/core`
- `src/tools` -> `packages/tools`
- `src/security` -> `packages/permissions`
- `src/secrets` -> `packages/secrets`
- `src/memory` + `extensions/memory-*` -> `packages/memory`
- `src/channels` + `extensions/* channel folders` -> `packages/channels`
- `src/plugin-sdk` + `packages/plugin-sdk` -> `packages/plugin-sdk`
- `ui` -> `apps/web`
- `src/cli` -> `apps/cli`

## Dominic Nexus runtime event bus

P05-T05 adds a local, in-process event bus owned by `packages/core`. Runtime
domain events use the shared `DomainEvent` vocabulary and deterministic runtime
utilities for event ids and timestamps. Audit remains a separate compliance
trail; the event bus is a local lifecycle/domain signal for runtime observers.

Audit and domain events currently draw event IDs from the same runtime
`idGenerator`, so their IDs may interleave when a single operation emits both
signals. This is deterministic and acceptable for now; split audit/domain ID
namespaces later only if compliance or storage requirements need independently
contiguous sequences.

`lifecycle.runtime_failed` is reserved for runtime infrastructure failures such
as transcript or session persistence failures. Provider failures use
`provider.call_failed`; the runtime is still considered healthy when a provider
lookup, permission decision, or execution path fails safely.

For P06-T03, provider execution audit should be consolidated so runner-level
`provider.call_requested`, `provider.call_succeeded`, and
`provider.call_failed` events remain the outer orchestration envelope while the
central provider execution path emits one `provider.call`-style audit event per
provider invocation.

## Dominic Nexus session routing and queues

P05-T07 adds core-owned session routing key helpers and per-session turn queue
behavior. CLI turns default to a deterministic JSON routing key derived from
`session.id`; future channel turns can derive a routing key from channel,
account, room, thread, and sender metadata without treating those identifiers
as authentication.

`AgentRunner` validates turn input and timeout options before enqueueing, then
serializes execution by routing key. Failures, cancellations, and timeouts are
recorded through the existing runner behavior and do not poison later queued
turns. Different routing keys can execute concurrently.

Routing keys are opaque queue identifiers for callers. The parser exists for
debugging and tests, not for authorization decisions. The current queue is
in-memory and FIFO per key; it does not implement cross-key fairness or durable
resume semantics.
