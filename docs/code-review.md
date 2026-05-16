# Dominic Nexus code review instructions

Review priority:

## Critical

- Secret values are logged, thrown, serialized, or exposed.
- Tool execution bypasses permission checks.
- Shell execution is possible without explicit approval.
- Filesystem write is possible without explicit approval.
- Network/provider call is possible without explicit approval.
- Plugin code can import or mutate internal runtime state directly.

## High

- Core runtime imports provider-specific, channel-specific, or UI-specific code.
- Config is loaded directly from env outside `packages/config`.
- Logging bypasses `packages/logging`.
- Tools bypass `ToolRegistry`.
- Provider calls bypass `ProviderRegistry`.

## Medium

- Missing tests around permissions, secrets, providers, tools, or runtime behavior.
- Missing cancellation/timeout handling for async operations.
- Global mutable state is introduced.
- Package boundaries become unclear.

## Low

- Naming is unclear.
- Repeated logic should be shared.
- Public types need documentation.

When reporting issues:

- Include file path.
- Include severity.
- Explain the failure mode.
- Suggest a concrete fix.