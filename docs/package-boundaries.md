# Dominic Nexus package boundaries

Last updated: 2026-05-14

This document defines package ownership and allowed dependencies for
`dominic-nexus`. It is the source for future import boundary tests.

The goal is to keep security-sensitive operations on the audited paths:
configuration through `packages/config`, logging through `packages/logging`,
audit through `packages/audit`, permissions through `packages/permissions`,
secrets through `packages/secrets`, tools through `packages/tools`, providers
through `packages/providers`, and runtime orchestration through
`packages/core`.

## Boundary principles

- Lower-level packages must not import higher-level orchestration packages.
- `packages/core` orchestrates. It should depend on contracts and registries,
  but feature packages should not depend back on core.
- Provider calls must go through `packages/providers`.
- Tool execution must go through `packages/tools`.
- Secret resolution must go through `packages/secrets`.
- Config loading and writes must go through `packages/config`.
- Logs must go through `packages/logging`.
- Plugins and channels must not reach into core internals.
- Apps may compose packages, but they should not duplicate runtime policy,
  provider, tool, secret, or config logic.

## Current packages

| Package | Owner responsibility | Notes |
| --- | --- | --- |
| `packages/shared` | Common IDs, JSON-safe types, Result/AppError, events, Clock, IdGenerator | Lowest-level package. Should not depend on other workspace packages. |
| `packages/config` | Source config, runtime config, validation, safe config writes | Must not perform provider/tool/secret execution. |
| `packages/logging` | Logger interface, structured logging, redaction, test logger | Must not import config or runtime to avoid logging cycles. |
| `packages/audit` | AuditEvent contracts, append-only sinks, and redacted audit serializers | Depends only on shared primitives and logging redaction. |
| `packages/permissions` | Permission requests, decisions, policies, approval abstractions | Must remain pure and testable; no direct CLI prompt dependency. |
| `packages/secrets` | SecretRef types, secret stores, secret resolver | May use permissions and logging redaction contracts, but must never log values. |
| `packages/memory` | Memory store interfaces and local memory implementations | Uses permission gates for read/write; no direct core dependency. |
| `packages/tools` | Tool definitions, registry, invocation pipeline, tool result types | All tool handlers execute through this package. |
| `packages/providers` | ModelRef, provider interfaces, provider registry, provider execution path | Provider adapters live here or register through plugins; no core imports. |
| `packages/channels` | Inbound/outbound channel contracts and channel access policy types | Channels normalize external messages; no core imports. |
| `packages/plugin-sdk` | Public plugin manifest and PluginApi contracts | Public surface only; no core internals. |
| `packages/core` | RuntimeContext, sessions, transcripts, AgentRunner, event bus, audit wiring | Orchestrates other packages and owns runtime lifecycle. |
| `apps/cli` | CLI process, chat UI, command parser, local approval prompts | Composes core and package APIs; no direct provider/tool bypass. |
| `apps/web` | Future local operator UI | Must call Gateway APIs, not import core internals directly. |

Future packages may include a Gateway package/app, a skill package, or
integration/plugin packages. They should follow the same direction: contracts
flow downward, orchestration stays in core or apps.

## Allowed import matrix

`yes` means direct workspace package imports are allowed. `no` means boundary
tests should reject the import. `limited` means only public contract imports are
allowed and the code should be reviewed before adding dependency edges. The
current import-boundary checker enforces allowed versus forbidden edges; it does
not emit warning-level diagnostics for `limited` edges.

| Importer | shared | config | logging | audit | permissions | secrets | memory | tools | providers | channels | plugin-sdk | core |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `packages/shared` | no | no | no | no | no | no | no | no | no | no | no | no |
| `packages/config` | yes | no | no | yes | no | no | no | no | no | no | limited | no |
| `packages/logging` | yes | no | no | no | no | no | no | no | no | no | no | no |
| `packages/audit` | yes | no | yes | no | no | no | no | no | no | no | no | no |
| `packages/permissions` | yes | no | no | yes | no | no | no | no | no | no | no | no |
| `packages/secrets` | yes | no | limited | yes | yes | no | no | no | no | no | no | no |
| `packages/memory` | yes | no | limited | yes | yes | no | no | no | no | no | limited | no |
| `packages/tools` | yes | no | limited | yes | yes | limited | limited | no | no | no | limited | no |
| `packages/providers` | yes | no | limited | yes | yes | limited | no | no | no | no | limited | no |
| `packages/channels` | yes | no | no | no | no | no | no | no | no | no | no | no |
| `packages/plugin-sdk` | yes | no | no | no | no | no | no | no | no | no | no | no |
| `packages/core` | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | limited | no |
| `apps/cli` | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes | limited | yes |
| `apps/web` | yes | no | no | no | no | no | no | no | no | no | limited | no |

## Package-specific rules

### `packages/shared`

Allowed:

- Type definitions.
- JSON-safe value helpers.
- Result and error primitives.
- Domain event types that do not import runtime implementations.
- Deterministic test-friendly primitives such as `Clock` and `IdGenerator`.

Forbidden:

- Importing any other workspace package.
- Reading process env, filesystem, network, or secrets.
- Logging side effects.

### `packages/config`

Allowed:

- Import `packages/shared`.
- Import plugin manifest/config schema contracts from `packages/plugin-sdk` only
  when validating plugin-provided config metadata.
- Read and write config files through explicit APIs.

Forbidden:

- Calling providers, tools, memory stores, channels, or core runtime.
- Resolving secret values.
- Logging raw config that may include SecretRefs or placeholders.
- Accepting unknown config keys.

### `packages/logging`

Allowed:

- Import `packages/shared`.
- Define logger interface, structured records, redaction helpers, and test
  logger.

Forbidden:

- Importing config, core, providers, tools, channels, or secrets.
- Resolving secrets.
- Adding telemetry sinks without explicit product approval and config.

### `packages/audit`

Allowed:

- Import `packages/shared`.
- Import logging redaction helpers.
- Define AuditEvent, AuditSink, in-memory test sinks, and redacted serializers.
- Store append-only event snapshots through explicit sink APIs.

Forbidden:

- Importing core, apps, providers, tools, channels, permissions, config,
  memory, or secrets.
- Resolving secrets or storing resolved secret values.
- Adding telemetry or remote audit sinks without explicit product approval and
  config.

### `packages/permissions`

Allowed:

- Import `packages/shared`.
- Define permission actions, requests, decisions, policy interfaces, and prompt
  abstractions.

Forbidden:

- Importing CLI code for prompts.
- Executing shell, filesystem, network, provider, tool, plugin, memory, or
  secret actions.
- Depending on core runtime state.

### `packages/secrets`

Allowed:

- Import `packages/shared`.
- Import `packages/permissions` for `secret.read` decisions.
- Import limited logging contracts or redaction helpers if needed.
- Read specific secret stores through explicit store implementations.

Forbidden:

- Logging resolved secret values.
- Throwing errors that contain resolved secret values.
- Importing `packages/core`.
- Returning secrets to audit or UI layers without explicit redaction.

### `packages/memory`

Allowed:

- Import `packages/shared`.
- Import `packages/permissions` for memory read/write checks.
- Import limited logging/redaction helpers.
- Import plugin SDK contracts only for future memory plugin capability types.

Forbidden:

- Importing `packages/core`.
- Calling providers directly for embeddings or summarization.
- Writing files outside approved roots.
- Treating memory plugin implementations as trusted before explicit enablement.

### `packages/tools`

Allowed:

- Import `packages/shared`.
- Import `packages/permissions`.
- Import limited logging/redaction helpers.
- Import `packages/secrets` only for tool implementations that explicitly need
  SecretRef resolution.
- Import `packages/memory` only for memory tool adapters.
- Import plugin SDK capability contracts.
- Define built-in tool registration helpers that keep raw tool definitions and
  handlers private.
- Apply layered permission checks for risky built-in tools when the registry
  check proves the caller may execute a capability class and the handler needs a
  resource-specific authorization decision. For example, the registry may check
  `filesystem.write` for `filesystem.write_file`, and the handler may then call
  a filesystem authorizer for the normalized target path before mutation. Tests
  and audit expectations should treat both decisions as intentional
  defense-in-depth, not as duplicate handler execution.

Forbidden:

- Importing `packages/core`.
- Calling provider adapters directly.
- Executing handlers outside the invocation pipeline.
- Performing filesystem writes, shell execution, or network requests without a
  permission decision and audit metadata.

### `packages/providers`

Allowed:

- Import `packages/shared`.
- Import `packages/permissions` for `provider.call` decisions.
- Import `packages/secrets` for credential resolution.
- Import limited logging/redaction helpers.
- Import plugin SDK provider capability contracts.

Forbidden:

- Importing `packages/core`.
- Importing `packages/tools` to execute tools directly.
- Importing `packages/channels`.
- Reading provider credentials directly from config or process env outside the
  secret abstraction.
- Running live network calls in unit tests.

### `packages/channels`

Allowed:

- Import `packages/shared`.
- Keep channel contracts minimal until channel access policy and plugin channel
  capability contracts are implemented.
- Add permissions, logging, audit, or plugin SDK imports only through a future
  docs and checker update that explains the new public contract edge.

Forbidden:

- Importing `packages/core`.
- Importing `packages/providers` or `packages/tools`.
- Treating sender/thread/session identifiers as authentication.
- Calling external services without future network policy integration.

### `packages/plugin-sdk`

Allowed:

- Import `packages/shared`.
- Define public manifest, capability, and PluginApi contracts.

Forbidden:

- Importing `packages/core`.
- Importing implementation packages such as providers, tools, channels, memory,
  secrets, config, logging, or permissions unless a future public contract is
  deliberately moved to shared.
- Re-exporting internal package internals.
- Exposing broad wildcard exports that make internals stable by accident.

### `packages/core`

Allowed:

- Import shared, config, logging, audit, permissions, secrets, memory, tools,
  providers, channels, and selected plugin SDK contracts.
- Own RuntimeContext, AgentRunner, session store, transcript store, event bus,
  and audit wiring.
- Compose provider and tool execution through their public package APIs.

Forbidden:

- Reading secrets directly from process env.
- Executing shell/network/filesystem operations directly.
- Duplicating provider/tool/permission/config logic.
- Importing app code.
- Treating Gateway auth or session IDs as multi-tenant isolation.

### `apps/cli`

Allowed:

- Import package public APIs.
- Own CLI argument parsing, stdin/stdout handling, and interactive approval
  prompt adapters.
- Compose runtime dependencies through `packages/core`.

Forbidden:

- Calling provider adapters directly in final runtime paths.
- Executing tools directly outside `packages/tools`.
- Reading or printing secret values.
- Mutating config files outside `packages/config`.

### `apps/web`

Allowed:

- Import `packages/shared` and `packages/plugin-sdk` types if useful for
  generated or shared UI contracts.
- Call future Gateway APIs.

Forbidden:

- Importing `packages/core` in browser/runtime UI code.
- Calling providers, tools, secrets, memory, config, or permissions directly.
- Displaying secret values.
- Sending telemetry without explicit user configuration.

## Cross-cutting forbidden edges

These import edges should be rejected by future boundary tests:

- `packages/providers` -> `packages/core`
- `packages/channels` -> `packages/core`
- `packages/plugin-sdk` -> `packages/core`
- `packages/plugin-sdk` -> implementation packages
- `packages/tools` -> `packages/core`
- `packages/memory` -> `packages/core`
- `packages/config` -> `packages/core`
- `packages/logging` -> `packages/core`
- `packages/permissions` -> `packages/core`
- `apps/web` -> `packages/core`

These behavior edges should also be rejected by tests or code review:

- provider execution outside `packages/providers`;
- tool execution outside `packages/tools`;
- config writes outside `packages/config`;
- secret reads outside `packages/secrets`;
- logging outside `packages/logging`;
- filesystem writes without `filesystem.write` permission;
- shell execution without `shell.execute` permission;
- network requests without `network.request` permission;
- plugin runtime import during metadata discovery.

## Future boundary tests

Add a test or script under `dominic-nexus/tests` or package-local tests that:

- scans TypeScript imports with a structured parser or a simple allowlist check;
- fails if a forbidden workspace import edge appears;
- treats `@dominic-nexus/*` imports as package edges;
- ignores generated files, build outputs, coverage, caches, and node_modules;
- has explicit fixtures for known-bad imports;
- runs through `pnpm.cmd test` or a documented `pnpm.cmd lint` subcheck.

Initial assertions should cover:

- providers cannot import core;
- channels cannot import core;
- plugin-sdk cannot import core or implementation packages;
- tools cannot import core;
- web UI cannot import core;
- shared cannot import any workspace package.

## Review checklist for new imports

Before adding a workspace import, answer:

- Is this dependency flowing from orchestration down to a capability package, or
  from a lower package up into orchestration?
- Could this import bypass a permission, audit, config, logging, tool, provider,
  secret, or channel boundary?
- Is the imported symbol a public contract or an implementation detail?
- Would this edge make a future plugin SDK/API commitment accidentally?
- Can the type move to `packages/shared` instead?
