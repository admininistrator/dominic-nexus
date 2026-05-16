import { afterEach, describe, expect, it } from "vitest";
import { InMemoryAuditSink, type AuditEvent, type AuditSink } from "@dominic-nexus/audit";
import type { PermissionDecision, PermissionRequest, PolicyEngine } from "@dominic-nexus/permissions";
import { FixedClock, REDACTED_PLACEHOLDER, SequentialIdGenerator, serializeAppError } from "@dominic-nexus/shared";
import {
  EnvSecretStore,
  ResolvedSecret,
  envSecret,
  resolveSecretRef,
  resolveSecretRefs,
  validateSecretRef
} from "./index.js";

const TEST_SECRET_KEY = "DOMINIC_NEXUS_TEST_SECRET";
const EMPTY_SECRET_KEY = "DOMINIC_NEXUS_EMPTY_SECRET";

class RecordingPolicy implements PolicyEngine {
  readonly requests: PermissionRequest[] = [];

  constructor(private readonly decision: PermissionDecision = { allowed: true }) {}

  decide(request: PermissionRequest): PermissionDecision {
    this.requests.push(request);
    return this.decision;
  }
}

class ThrowingPolicy implements PolicyEngine {
  decide(): PermissionDecision {
    throw new Error("approval prompt failed with test-secret-value");
  }
}

class FailingAuditSink implements AuditSink {
  private appendCount = 0;

  constructor(private readonly failOnAppendNumber: number) {}

  async append(_event: AuditEvent): Promise<void> {
    this.appendCount += 1;

    if (this.appendCount === this.failOnAppendNumber) {
      throw new Error("audit sink failed with audit-secret-value");
    }
  }
}

function createAuditContext() {
  const audit = new InMemoryAuditSink();

  return {
    audit,
    context: {
      audit,
      clock: new FixedClock("2026-05-08T00:00:00.000Z"),
      idGenerator: new SequentialIdGenerator({ eventPrefix: "secret-audit" })
    }
  };
}

afterEach(() => {
  delete process.env[TEST_SECRET_KEY];
  delete process.env[EMPTY_SECRET_KEY];
});

describe("validateSecretRef", () => {
  it("accepts the env-backed SecretRef object schema", () => {
    expect(validateSecretRef({ provider: "env", key: TEST_SECRET_KEY })).toEqual({
      ok: true,
      value: {
        provider: "env",
        key: TEST_SECRET_KEY
      }
    });
  });

  it("rejects non-object SecretRef values", () => {
    for (const value of ["env:OPENAI_API_KEY", null, []]) {
      const result = validateSecretRef(value);

      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.error.code).toBe("secret.invalid_ref");
      }
    }
  });

  it("rejects unknown SecretRef keys and providers", () => {
    const unknownKey = validateSecretRef({
      provider: "env",
      key: TEST_SECRET_KEY,
      value: "test-secret-value"
    });
    expect(unknownKey.ok).toBe(false);
    if (!unknownKey.ok) {
      expect(serializeAppError(unknownKey.error)).toEqual({
        name: "AppError",
        code: "secret.invalid_ref",
        message: "SecretRef contains unknown keys",
        context: {
          unknownKeys: ["value"]
        }
      });
      expect(JSON.stringify(serializeAppError(unknownKey.error))).not.toContain("test-secret-value");
    }

    const unknownProvider = validateSecretRef({
      provider: "file",
      key: TEST_SECRET_KEY
    });
    expect(unknownProvider.ok).toBe(false);
    if (!unknownProvider.ok) {
      expect(serializeAppError(unknownProvider.error)).toMatchObject({
        code: "secret.invalid_ref",
        message: "SecretRef provider must be env"
      });
    }
  });

  it("rejects empty and malformed environment names", () => {
    for (const key of ["", " OPENAI_API_KEY", "OPENAI API KEY", "1OPENAI_API_KEY", "OPENAI\0API_KEY"]) {
      const result = validateSecretRef({
        provider: "env",
        key
      });

      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.error.code).toBe("secret.invalid_ref");
      }
    }
  });
});

describe("ResolvedSecret", () => {
  it("exposes the value only through an explicit method and serializes redacted", () => {
    const secret = new ResolvedSecret("test-secret-value");

    expect(secret.reveal()).toBe("test-secret-value");
    expect(String(secret)).toBe(REDACTED_PLACEHOLDER);
    expect(`${secret}`).toBe(REDACTED_PLACEHOLDER);
    expect(JSON.stringify({ secret })).toBe(`{"secret":"${REDACTED_PLACEHOLDER}"}`);
    expect(JSON.stringify({ secret })).not.toContain("test-secret-value");
  });
});

describe("EnvSecretStore", () => {
  it("checks secret.read permission before reading an environment secret", async () => {
    process.env[TEST_SECRET_KEY] = "test-secret-value";
    const policy = new RecordingPolicy();
    const store = new EnvSecretStore(policy);

    await expect(store.read(envSecret(TEST_SECRET_KEY))).resolves.toBe("test-secret-value");

    expect(policy.requests).toEqual([
      {
        action: "secret.read",
        reason: "Read secret from environment",
        resource: TEST_SECRET_KEY
      }
    ]);
  });

  it("does not read the environment when secret.read permission is denied", async () => {
    let envWasRead = false;
    const env = new Proxy<Record<string, string | undefined>>(
      {
        [TEST_SECRET_KEY]: "test-secret-value"
      },
      {
        get(target, property) {
          if (property === TEST_SECRET_KEY) {
            envWasRead = true;
          }

          return target[property as string];
        }
      }
    );
    const store = new EnvSecretStore(
      new RecordingPolicy({ allowed: false, reason: "secret denied" }),
      undefined,
      env
    );

    await expect(store.read(envSecret(TEST_SECRET_KEY))).rejects.toMatchObject({
      code: "secret.read_denied"
    });
    expect(envWasRead).toBe(false);
  });

  it("audits allowed secret reads without storing the secret value", async () => {
    process.env[TEST_SECRET_KEY] = "test-secret-value";
    const { audit, context } = createAuditContext();
    const store = new EnvSecretStore(new RecordingPolicy(), context);

    await expect(store.read(envSecret(TEST_SECRET_KEY))).resolves.toBe("test-secret-value");

    const events = audit.listEvents();
    expect(events).toEqual([
      expect.objectContaining({
        action: "permission.decide",
        decision: "allowed",
        outcome: "succeeded"
      }),
      expect.objectContaining({
        action: "secret.read",
        decision: "allowed",
        outcome: "succeeded",
        resource: expect.objectContaining({
          type: "secret",
          id: TEST_SECRET_KEY
        }),
        metadata: {
          provider: "env",
          found: true
        }
      })
    ]);
    expect(JSON.stringify(events)).not.toContain("test-secret-value");
  });

  it("audits missing environment secrets without storing a value", async () => {
    const { audit, context } = createAuditContext();
    const store = new EnvSecretStore(new RecordingPolicy(), context);

    await expect(store.read(envSecret(TEST_SECRET_KEY))).resolves.toBeUndefined();

    expect(audit.listEvents()).toEqual([
      expect.objectContaining({
        action: "permission.decide",
        decision: "allowed",
        outcome: "succeeded"
      }),
      expect.objectContaining({
        action: "secret.read",
        decision: "allowed",
        outcome: "succeeded",
        metadata: {
          provider: "env",
          found: false
        }
      })
    ]);
  });

  it("throws a safe AppError when secret.read permission is denied", async () => {
    process.env[TEST_SECRET_KEY] = "test-secret-value";
    const store = new EnvSecretStore(new RecordingPolicy({ allowed: false, reason: "secret denied" }));

    try {
      await store.read(envSecret(TEST_SECRET_KEY));
      throw new Error("Expected secret read to fail");
    } catch (error) {
      expect(serializeAppError(error)).toEqual({
        name: "AppError",
        code: "secret.read_denied",
        message: "Secret read denied",
        context: {
          provider: "env",
          secretRef: REDACTED_PLACEHOLDER
        }
      });
    }
  });

  it("throws the safe denial error when denied-read audit append fails", async () => {
    process.env[TEST_SECRET_KEY] = "test-secret-value";
    const store = new EnvSecretStore(
      new RecordingPolicy({ allowed: false, reason: "secret denied" }),
      {
        audit: new FailingAuditSink(2),
        clock: new FixedClock("2026-05-08T00:00:00.000Z"),
        idGenerator: new SequentialIdGenerator({ eventPrefix: "secret-audit" })
      }
    );

    try {
      await store.read(envSecret(TEST_SECRET_KEY));
      throw new Error("Expected secret read to fail");
    } catch (error) {
      expect(serializeAppError(error)).toEqual({
        name: "AppError",
        code: "secret.read_denied",
        message: "Secret read denied",
        context: {
          provider: "env",
          secretRef: REDACTED_PLACEHOLDER
        }
      });
      expect(JSON.stringify(serializeAppError(error))).not.toContain("audit-secret-value");
      expect(JSON.stringify(serializeAppError(error))).not.toContain("test-secret-value");
    }
  });

  it("audits denied secret reads without storing the secret value", async () => {
    process.env[TEST_SECRET_KEY] = "test-secret-value";
    const { audit, context } = createAuditContext();
    const store = new EnvSecretStore(new RecordingPolicy({ allowed: false, reason: "secret denied" }), context);

    await expect(store.read(envSecret(TEST_SECRET_KEY))).rejects.toMatchObject({
      code: "secret.read_denied"
    });

    const events = audit.listEvents();
    expect(events).toEqual([
      expect.objectContaining({
        action: "permission.decide",
        decision: "denied",
        outcome: "denied"
      }),
      expect.objectContaining({
        action: "secret.read",
        decision: "denied",
        outcome: "denied",
        resource: expect.objectContaining({
          type: "secret",
          id: TEST_SECRET_KEY
        })
      })
    ]);
    expect(JSON.stringify(events)).not.toContain("test-secret-value");
  });

  it("audits secret permission check failures without storing the secret value", async () => {
    process.env[TEST_SECRET_KEY] = "test-secret-value";
    const { audit, context } = createAuditContext();
    const store = new EnvSecretStore(new ThrowingPolicy(), context);

    try {
      await store.read(envSecret(TEST_SECRET_KEY));
      throw new Error("Expected secret permission check to fail");
    } catch (error) {
      expect(serializeAppError(error)).toEqual({
        name: "AppError",
        code: "unexpected",
        message: "Secret read permission check failed",
        context: {
          provider: "env",
          secretRef: REDACTED_PLACEHOLDER
        }
      });
    }

    const events = audit.listEvents();
    expect(events).toEqual([
      expect.objectContaining({
        action: "secret.read",
        decision: "not_applicable",
        outcome: "failed",
        resource: expect.objectContaining({
          type: "secret",
          id: TEST_SECRET_KEY
        }),
        metadata: {
          provider: "env",
          errorName: "Error"
        }
      })
    ]);
    expect(JSON.stringify(events)).not.toContain("test-secret-value");
  });

  it("throws the safe permission-check error when failure audit append fails", async () => {
    process.env[TEST_SECRET_KEY] = "test-secret-value";
    const store = new EnvSecretStore(
      new ThrowingPolicy(),
      {
        audit: new FailingAuditSink(1),
        clock: new FixedClock("2026-05-08T00:00:00.000Z"),
        idGenerator: new SequentialIdGenerator({ eventPrefix: "secret-audit" })
      }
    );

    try {
      await store.read(envSecret(TEST_SECRET_KEY));
      throw new Error("Expected secret permission check to fail");
    } catch (error) {
      expect(serializeAppError(error)).toEqual({
        name: "AppError",
        code: "unexpected",
        message: "Secret read permission check failed",
        context: {
          provider: "env",
          secretRef: REDACTED_PLACEHOLDER
        }
      });
      expect(JSON.stringify(serializeAppError(error))).not.toContain("audit-secret-value");
      expect(JSON.stringify(serializeAppError(error))).not.toContain("test-secret-value");
    }
  });
});

describe("resolveSecretRef", () => {
  it("resolves an active env secret into an opaque value", async () => {
    const store = new EnvSecretStore(new RecordingPolicy(), undefined, {
      [TEST_SECRET_KEY]: "test-secret-value"
    });

    const result = await resolveSecretRef(envSecret(TEST_SECRET_KEY), {
      name: "openaiApiKey",
      active: true,
      store
    });

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value).toMatchObject({
        status: "resolved",
        name: "openaiApiKey",
        provider: "env"
      });
      if (result.value.status === "resolved") {
        expect(result.value.secret.reveal()).toBe("test-secret-value");
        expect(JSON.stringify(result.value)).not.toContain("test-secret-value");
      }
    }
  });

  it("fails closed when an active env secret is missing", async () => {
    const store = new EnvSecretStore(new RecordingPolicy(), undefined, {});

    const result = await resolveSecretRef(envSecret(TEST_SECRET_KEY), {
      name: "openaiApiKey",
      active: true,
      store
    });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(serializeAppError(result.error)).toEqual({
        name: "AppError",
        code: "secret.unresolved",
        message: "Active secret could not be resolved",
        context: {
          name: "openaiApiKey",
          provider: "env",
          status: "unresolved"
        }
      });
      expect(JSON.stringify(serializeAppError(result.error))).not.toContain(TEST_SECRET_KEY);
    }
  });

  it("fails closed when an active env secret is empty", async () => {
    const store = new EnvSecretStore(new RecordingPolicy(), undefined, {
      [EMPTY_SECRET_KEY]: ""
    });

    const result = await resolveSecretRef(envSecret(EMPTY_SECRET_KEY), {
      name: "emptyApiKey",
      active: true,
      store
    });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe("secret.unresolved");
    }
  });

  it("returns a warning when an inactive env secret is missing", async () => {
    const store = new EnvSecretStore(new RecordingPolicy(), undefined, {});

    await expect(
      resolveSecretRef(envSecret(TEST_SECRET_KEY), {
        name: "optionalApiKey",
        active: false,
        store
      })
    ).resolves.toEqual({
      ok: true,
      value: {
        status: "warning",
        warning: {
          name: "optionalApiKey",
          provider: "env",
          status: "unresolved"
        }
      }
    });
  });

  it("returns a warning when an inactive env secret is denied", async () => {
    let envWasRead = false;
    const env = new Proxy<Record<string, string | undefined>>(
      {
        [TEST_SECRET_KEY]: "test-secret-value"
      },
      {
        get(target, property) {
          if (property === TEST_SECRET_KEY) {
            envWasRead = true;
          }

          return target[property as string];
        }
      }
    );
    const store = new EnvSecretStore(new RecordingPolicy({ allowed: false, reason: "secret denied" }), undefined, env);

    await expect(
      resolveSecretRef(envSecret(TEST_SECRET_KEY), {
        name: "optionalApiKey",
        active: false,
        store
      })
    ).resolves.toEqual({
      ok: true,
      value: {
        status: "warning",
        warning: {
          name: "optionalApiKey",
          provider: "env",
          status: "permission_denied"
        }
      }
    });
    expect(envWasRead).toBe(false);
  });

  it("fails validation for inactive malformed refs instead of warning", async () => {
    const result = await resolveSecretRef(
      {
        provider: "env",
        key: "not valid"
      },
      {
        name: "optionalApiKey",
        active: false,
        store: new EnvSecretStore(new RecordingPolicy(), undefined, {})
      }
    );

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe("secret.invalid_ref");
    }
  });

  it("returns a runtime setup error when no store is provided", async () => {
    const result = await resolveSecretRef(envSecret(TEST_SECRET_KEY), {
      name: "optionalApiKey",
      active: false
    });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(serializeAppError(result.error)).toEqual({
        name: "AppError",
        code: "unexpected",
        message: "Secret resolver requires a secret store",
        context: {
          name: "optionalApiKey",
          provider: "env"
        }
      });
      expect(JSON.stringify(serializeAppError(result.error))).not.toContain(TEST_SECRET_KEY);
    }
  });

  it("does not leak secret values in resolver errors or audit events", async () => {
    const { audit, context } = createAuditContext();
    const store = new EnvSecretStore(new RecordingPolicy({ allowed: false, reason: "secret denied" }), context, {
      [TEST_SECRET_KEY]: "test-secret-value"
    });

    const result = await resolveSecretRef(envSecret(TEST_SECRET_KEY), {
      name: "openaiApiKey",
      active: true,
      store
    });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(JSON.stringify(serializeAppError(result.error))).not.toContain("test-secret-value");
    }
    expect(JSON.stringify(audit.listEvents())).not.toContain("test-secret-value");
  });
});

describe("resolveSecretRefs", () => {
  it("returns deterministic active secrets and inactive warnings", async () => {
    const store = new EnvSecretStore(new RecordingPolicy(), undefined, {
      DOMINIC_NEXUS_ALPHA_SECRET: "alpha-secret-value"
    });

    const result = await resolveSecretRefs(
      [
        {
          name: "zOptional",
          ref: envSecret("DOMINIC_NEXUS_Z_SECRET"),
          active: false
        },
        {
          name: "alpha",
          ref: envSecret("DOMINIC_NEXUS_ALPHA_SECRET"),
          active: true
        }
      ],
      {
        store
      }
    );

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(Object.keys(result.value.secrets)).toEqual(["alpha"]);
      expect(result.value.secrets.alpha?.reveal()).toBe("alpha-secret-value");
      expect(result.value.warnings).toEqual([
        {
          name: "zOptional",
          provider: "env",
          status: "unresolved"
        }
      ]);
      expect(JSON.stringify(result.value)).not.toContain("alpha-secret-value");
    }
  });
});
