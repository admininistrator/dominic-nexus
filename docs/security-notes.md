# Dominic Nexus security notes

Last updated: 2026-05-08

These notes define the security and trust model for Dominic Nexus before the
project adds powerful tools, real providers, plugins, channels, Gateway/RPC, or
web UI surfaces.

Dominic Nexus is a private, local-first personal assistant. Its security goal is
to reduce accidental exposure and unsafe local actions, not to provide hostile
multi-tenant isolation.

## Hard requirements

- Shell execution is deny-by-default.
- Filesystem writes are deny-by-default.
- Network requests are deny-by-default.
- Provider calls are deny-by-default.
- Plugin execution is deny-by-default.
- Secret reads are deny-by-default.
- Risky actions require explicit policy allow or user approval.
- Every sensitive decision should emit an audit event.
- No silent telemetry is allowed.
- Secret values must never be logged, printed, stored in audit metadata, or
  included in thrown error messages.
- Product code must go through the package boundaries defined by
  `dominic-nexus/AGENTS.md`: config through `packages/config`, logging through
  `packages/logging`, tools through `packages/tools`, providers through
  `packages/providers`, and policy through `packages/permissions`.

## Trust model

Dominic Nexus assumes one trusted local operator boundary per local runtime.
That operator is the person controlling the machine, config, state directory,
CLI, and future local Gateway credentials.

Gateway callers are trusted operators once authenticated. They are not modeled
as hostile tenants. Gateway auth prevents accidental or unauthorized local
access, but it is not a sandbox for mutually distrustful users. Session IDs,
session keys, thread IDs, and channel IDs are routing controls, not
authorization boundaries.

The runtime should still fail closed. Trusting the local operator does not mean
silent execution is acceptable. Provider calls, network, shell, filesystem
writes, plugin execution, and secret reads still need explicit policy and audit
because they can leak data, spend money, mutate local state, or run arbitrary
code.

## Actors and boundaries

| Actor or surface | Trust level | Boundary rule |
| --- | --- | --- |
| Local CLI user | Trusted operator | May approve risky actions interactively; output must not reveal secrets. |
| Local Gateway caller | Trusted operator after authentication | Full operator access, but still routed through policy and audit. |
| Web UI | Trusted local operator interface | Must call Gateway APIs, not bypass core policy. |
| Channel sender | Untrusted ingress until channel policy allows trigger | DM/group/mention policy decides whether a message can trigger the agent. |
| Supplemental channel context | Untrusted content | Visibility is separate from trigger authorization. |
| Provider adapter | Trusted adapter code with untrusted remote service | Credentials through SecretRef; requests require provider and network policy. |
| Tool handler | Trusted local code with risky effects | Must execute only through the tool registry and permission pipeline. |
| Plugin runtime | Trusted code only after explicit enablement | Discovery must use metadata without importing runtime code. |
| Skill folder | Local content, not automatically executable | Discovery must be root-bounded and symlink-safe. |
| Config file | Local trusted input with strict validation | Unknown and malformed config fails closed. |
| Memory and transcripts | Sensitive local state | Reads/writes should be explicit, bounded, and audited where sensitive. |

## Default deny surfaces

### Shell execution

Shell execution is disabled by default. Future shell support must require:

- `shell.execute` permission;
- explicit approval or config allowlist;
- exact command, cwd, env, timeout, and output limits in the audited request;
- rejection of risky environment overrides such as `PATH`, `LD_*`, and
  `DYLD_*` unless specifically justified;
- Windows-aware behavior for PowerShell and `cmd`.

### Filesystem writes

Filesystem writes are disabled by default. Future write support must require:

- `filesystem.write` permission;
- normalized absolute paths;
- approved root containment;
- symlink escape checks where applicable;
- audit records for path, operation, decision, and outcome.

Read-only filesystem tools may be selected earlier, but they still need root
bounds, size limits, and binary/large-file handling.

### Network requests

Network requests are disabled by default. Future network tools and provider
transports must require:

- `network.request` permission;
- explicit host/resource metadata;
- response size and content-type limits where applicable;
- no sensitive headers or credentials in logs/audit.

### Provider calls

Provider calls are disabled by default until policy allows them. Provider
execution must:

- go through `packages/providers`;
- use `provider.call` permission;
- resolve credentials only through `packages/secrets`;
- audit provider name, model ref, decision, outcome, and safe usage metadata;
- avoid live network in unit tests.

### Plugin execution

Plugin execution is disabled by default. Plugin handling must:

- parse manifest metadata before runtime import;
- require explicit allowlist or `plugin.execute` approval;
- treat enabled plugins as trusted in-process code;
- prevent plugin SDK imports from exposing core internals;
- replace registry snapshots safely instead of mutating global state in place.

### Secret reads

Secret reads are disabled by default. Secret handling must:

- represent credentials as SecretRef values in config;
- resolve active secrets into runtime snapshots only after policy allows;
- never log, print, audit, or throw resolved secret values;
- fail closed for unresolved active secrets;
- avoid writing redacted placeholders back to config.

## Channel trust

Channels are untrusted ingress. A channel message should not automatically
trigger an agent turn just because the channel adapter can read it.

Required channel controls:

- sender identity normalization;
- account, room, thread, and channel metadata;
- DM allowlist policy;
- group mention required by default;
- trigger authorization separated from supplemental context visibility;
- `NO_REPLY` and `no_reply` response filtering;
- duplicate visible confirmation suppression for messaging tools.

External channel plugins are deferred until secrets, network policy, session
routing, audit, and plugin loading are hardened.

## Gateway and local UI trust

The future Gateway is a local control plane and policy boundary. It should not
bind publicly by default.

Required Gateway controls:

- authenticated local HTTP and WebSocket APIs;
- WebSocket first frame must be `connect`;
- side-effecting RPC calls need idempotency keys;
- event streams must be redacted;
- Gateway credentials grant operator-level access and must be protected as
  secrets;
- remote or tailnet exposure must be explicit and documented.

The web UI should call Gateway APIs only. It must not import core internals or
call providers/tools directly.

## Config and state safety

Config must be strict and fail closed:

- reject unknown keys;
- reject malformed values;
- keep source config separate from runtime config;
- never continue with partially applied config;
- never promote redacted placeholders to valid config;
- require filesystem write permission for config mutations.

The initial strict source config accepts only `appName`, `environment`,
`logLevel`, `secrets`, and `stateDirectory`. Runtime defaults are applied after
source validation. Environment overrides are intentionally narrow:
`DOMINIC_NEXUS_CONFIG_PATH`, `DOMINIC_NEXUS_APP_NAME`,
`DOMINIC_NEXUS_STATE_DIRECTORY`, `DOMINIC_NEXUS_LOG_LEVEL`, and `NODE_ENV`.

State files such as sessions, transcripts, audit logs, and memory are sensitive
local data. They should be stored under configured roots, use safe path helpers,
and avoid secret values.

## Audit requirements

Audit events should be append-only and JSON-safe. They should include:

- timestamp;
- action;
- actor or session when available;
- resource;
- decision;
- policy source when useful;
- outcome;
- safe metadata.

Audit events must not include:

- resolved secret values;
- raw authorization headers;
- cookies;
- full provider credentials;
- unbounded tool output;
- sensitive file content unless the user explicitly requested a safe export.

## Differences from OpenClaw defaults

Dominic Nexus intentionally differs from the reference in these ways:

- stricter deny-by-default posture for shell, filesystem write, network,
  provider, plugin, and secret access;
- provider calls require explicit policy/approval until configured otherwise;
- shell execution is not a normal early capability;
- external channels are not enabled early;
- plugins require explicit enablement and are documented as trusted code;
- broad provider/channel/media extension catalogs are deferred;
- no silent telemetry exists as a default or background behavior;
- auditability is a core requirement before adding powerful integrations;
- local Markdown memory comes before semantic/vector memory;
- Gateway/web UI are added only after CLI/core runtime boundaries are stable;
- native/mobile apps and large release/deployment machinery are out of current
  scope.

## Security test targets

Future tests should prove:

- default policy denies shell, network, filesystem write, provider, plugin, and
  secret reads;
- approval policy is deterministic in tests;
- secret values do not appear in logs, audit events, errors, CLI output, or UI
  payloads;
- filesystem root bounds reject traversal and symlink escapes;
- provider and tool calls cannot bypass the registry/policy path;
- invalid config fails closed;
- channel trigger authorization is separate from context visibility;
- plugin discovery does not import runtime code;
- Gateway event streams are redacted.
