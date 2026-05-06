import { afterEach, describe, expect, it } from "vitest";
import type { PermissionDecision, PermissionRequest, PolicyEngine } from "@dominic-nexus/permissions";
import { EnvSecretStore, envSecret } from "./index.js";

const TEST_SECRET_KEY = "DOMINIC_NEXUS_TEST_SECRET";

class RecordingPolicy implements PolicyEngine {
  readonly requests: PermissionRequest[] = [];

  constructor(private readonly decision: PermissionDecision = { allowed: true }) {}

  decide(request: PermissionRequest): PermissionDecision {
    this.requests.push(request);
    return this.decision;
  }
}

afterEach(() => {
  delete process.env[TEST_SECRET_KEY];
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

  it("throws when secret.read permission is denied", async () => {
    process.env[TEST_SECRET_KEY] = "test-secret-value";
    const store = new EnvSecretStore(new RecordingPolicy({ allowed: false, reason: "secret denied" }));

    await expect(store.read(envSecret(TEST_SECRET_KEY))).rejects.toThrow("secret denied");
  });
});
