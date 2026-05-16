import { inspect } from "node:util";
import { appendAuditEvent, type OptionalAuditRuntimeContext } from "@dominic-nexus/audit";
import { decidePermissionWithAudit, type PermissionDecision, type PolicyEngine } from "@dominic-nexus/permissions";
import { AppError, err, ok, REDACTED_PLACEHOLDER, type Result } from "@dominic-nexus/shared";

export interface SecretRef {
  provider: "env";
  key: string;
}

export type SecretEnvSource = Record<string, string | undefined>;

export interface SecretStore {
  read(ref: SecretRef): Promise<string | undefined>;
}

export interface SecretResolutionEntry {
  name: string;
  ref: SecretRef;
  active: boolean;
}

export type SecretResolutionWarningStatus = "unresolved" | "permission_denied";

export interface SecretResolutionWarning {
  name: string;
  provider: SecretRef["provider"];
  status: SecretResolutionWarningStatus;
}

export type SecretResolution =
  | {
      status: "resolved";
      name: string;
      provider: SecretRef["provider"];
      secret: ResolvedSecret;
    }
  | {
      status: "warning";
      warning: SecretResolutionWarning;
    };

export interface SecretResolutionSnapshot {
  secrets: Record<string, ResolvedSecret>;
  warnings: SecretResolutionWarning[];
}

export interface ResolveSecretRefOptions {
  name?: string;
  active?: boolean;
  store?: SecretStore;
}

export interface ResolveSecretRefsOptions {
  store?: SecretStore;
}

const SECRET_REF_KEYS = new Set(["provider", "key"]);
const ENV_SECRET_KEY_PATTERN = /^[A-Za-z_][A-Za-z0-9_]*$/u;

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function secretInvalidRef(message: string, context?: Record<string, string | string[]>): Result<never> {
  const options: {
    code: "secret.invalid_ref";
    message: string;
    context?: Record<string, string | string[]>;
  } = {
    code: "secret.invalid_ref",
    message
  };

  if (context !== undefined) {
    options.context = context;
  }

  return err(new AppError(options));
}

function createUnresolvedSecretError(name: string, provider: SecretRef["provider"]): AppError {
  return new AppError({
    code: "secret.unresolved",
    message: "Active secret could not be resolved",
    context: {
      name,
      provider,
      status: "unresolved"
    }
  });
}

function createSafeUnexpectedSecretError(ref: SecretRef): AppError {
  return new AppError({
    code: "unexpected",
    message: "Secret read permission check failed",
    context: {
      provider: ref.provider,
      secretRef: ref.key
    }
  });
}

async function appendSecretAuditEventSafely(
  auditContext: OptionalAuditRuntimeContext | undefined,
  event: Parameters<typeof appendAuditEvent>[1]
): Promise<void> {
  try {
    await appendAuditEvent(auditContext, event);
  } catch {
    // Audit failures must not shadow safe secret errors.
  }
}

function normalizeSecretName(value: string | undefined): Result<string> {
  if (value === undefined) {
    return ok("secret");
  }

  if (value.trim().length === 0) {
    return secretInvalidRef("Secret name must be a non-empty string", {
      field: "name"
    });
  }

  return ok(value);
}

export class ResolvedSecret {
  readonly #value: string;

  constructor(value: string) {
    this.#value = value;
  }

  reveal(): string {
    return this.#value;
  }

  toJSON(): string {
    return REDACTED_PLACEHOLDER;
  }

  toString(): string {
    return REDACTED_PLACEHOLDER;
  }

  [Symbol.toPrimitive](): string {
    return REDACTED_PLACEHOLDER;
  }

  [inspect.custom](): string {
    return REDACTED_PLACEHOLDER;
  }
}

export class EnvSecretStore implements SecretStore {
  constructor(
    private readonly policy: PolicyEngine,
    private readonly auditContext?: OptionalAuditRuntimeContext,
    private readonly env: SecretEnvSource = process.env
  ) {}

  async read(ref: SecretRef): Promise<string | undefined> {
    let decision: PermissionDecision;

    try {
      decision = await decidePermissionWithAudit(this.policy, {
        action: "secret.read",
        reason: "Read secret from environment",
        resource: ref.key
      }, this.auditContext);
    } catch (error) {
      await appendSecretAuditEventSafely(this.auditContext, {
        sourcePackage: "@dominic-nexus/secrets",
        action: "secret.read",
        decision: "not_applicable",
        resource: {
          type: "secret",
          id: ref.key,
          name: ref.key
        },
        outcome: "failed",
        metadata: {
          provider: ref.provider,
          errorName: error instanceof Error ? error.name : "UnknownError"
        }
      });

      throw createSafeUnexpectedSecretError(ref);
    }

    if (!decision.allowed) {
      await appendSecretAuditEventSafely(this.auditContext, {
        sourcePackage: "@dominic-nexus/secrets",
        action: "secret.read",
        decision: "denied",
        resource: {
          type: "secret",
          id: ref.key,
          name: ref.key
        },
        outcome: "denied",
        metadata: {
          provider: ref.provider
        }
      });

      throw new AppError({
        code: "secret.read_denied",
        message: "Secret read denied",
        context: {
          provider: ref.provider,
          secretRef: ref.key
        }
      });
    }

    const value = this.env[ref.key];

    await appendAuditEvent(this.auditContext, {
      sourcePackage: "@dominic-nexus/secrets",
      action: "secret.read",
      decision: "allowed",
      resource: {
        type: "secret",
        id: ref.key,
        name: ref.key
      },
      outcome: "succeeded",
      metadata: {
        provider: ref.provider,
        found: value !== undefined
      }
    });

    return value;
  }
}

export function validateSecretRef(input: unknown): Result<SecretRef> {
  if (!isRecord(input)) {
    return secretInvalidRef("SecretRef must be an object");
  }

  const unknownKeys = Object.keys(input).filter((key) => !SECRET_REF_KEYS.has(key));
  if (unknownKeys.length > 0) {
    return secretInvalidRef("SecretRef contains unknown keys", {
      unknownKeys: unknownKeys.sort()
    });
  }

  if (input.provider !== "env") {
    return secretInvalidRef("SecretRef provider must be env", {
      field: "provider"
    });
  }

  if (typeof input.key !== "string" || input.key.length === 0) {
    return secretInvalidRef("SecretRef key must be a non-empty string", {
      field: "key"
    });
  }

  if (input.key.trim() !== input.key || input.key.includes("\0") || !ENV_SECRET_KEY_PATTERN.test(input.key)) {
    return secretInvalidRef("SecretRef key must be a valid environment variable name", {
      field: "key"
    });
  }

  return ok({
    provider: "env",
    key: input.key
  });
}

export async function resolveSecretRef(ref: unknown, options: ResolveSecretRefOptions = {}): Promise<Result<SecretResolution>> {
  const parsedRef = validateSecretRef(ref);
  if (!parsedRef.ok) {
    return parsedRef;
  }

  const name = normalizeSecretName(options.name);
  if (!name.ok) {
    return name;
  }

  const active = options.active ?? true;
  const store = options.store;
  if (store === undefined) {
    return err(
      new AppError({
        code: "unexpected",
        message: "Secret resolver requires a secret store",
        context: {
          name: name.value,
          provider: parsedRef.value.provider
        }
      })
    );
  }

  let value: string | undefined;

  try {
    value = await store.read(parsedRef.value);
  } catch (error) {
    if (error instanceof AppError && error.code === "secret.read_denied" && !active) {
      return ok({
        status: "warning",
        warning: {
          name: name.value,
          provider: parsedRef.value.provider,
          status: "permission_denied"
        }
      });
    }

    return err(
      error instanceof AppError
        ? error
        : new AppError({
            code: "unexpected",
            message: "Secret resolution failed",
            context: {
              name: name.value,
              provider: parsedRef.value.provider
            }
          })
    );
  }

  if (value === undefined || value.length === 0) {
    if (!active) {
      return ok({
        status: "warning",
        warning: {
          name: name.value,
          provider: parsedRef.value.provider,
          status: "unresolved"
        }
      });
    }

    return err(createUnresolvedSecretError(name.value, parsedRef.value.provider));
  }

  return ok({
    status: "resolved",
    name: name.value,
    provider: parsedRef.value.provider,
    secret: new ResolvedSecret(value)
  });
}

export async function resolveSecretRefs(
  entries: readonly SecretResolutionEntry[],
  options: ResolveSecretRefsOptions = {}
): Promise<Result<SecretResolutionSnapshot>> {
  const snapshot: SecretResolutionSnapshot = {
    secrets: {},
    warnings: []
  };

  const sortedEntries = [...entries].sort((left, right) => left.name.localeCompare(right.name));

  for (const entry of sortedEntries) {
    const resolveOptions: ResolveSecretRefOptions = {
      name: entry.name,
      active: entry.active
    };

    if (options.store !== undefined) {
      resolveOptions.store = options.store;
    }

    const result = await resolveSecretRef(entry.ref, resolveOptions);

    if (!result.ok) {
      return result;
    }

    if (result.value.status === "warning") {
      snapshot.warnings.push(result.value.warning);
      continue;
    }

    if (entry.active) {
      snapshot.secrets[entry.name] = result.value.secret;
    }
  }

  return ok(snapshot);
}

export function envSecret(key: string): SecretRef {
  return {
    provider: "env",
    key
  };
}
