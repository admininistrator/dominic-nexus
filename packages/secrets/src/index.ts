import type { PolicyEngine } from "@dominic-nexus/permissions";

export interface SecretRef {
  provider: "env";
  key: string;
}

export interface SecretStore {
  read(ref: SecretRef): Promise<string | undefined>;
}

export class EnvSecretStore implements SecretStore {
  constructor(private readonly policy: PolicyEngine) {}

  async read(ref: SecretRef): Promise<string | undefined> {
    const decision = await this.policy.decide({
      action: "secret.read",
      reason: "Read secret from environment",
      resource: ref.key
    });

    if (!decision.allowed) {
      throw new Error(decision.reason);
    }

    return process.env[ref.key];
  }
}

export function envSecret(key: string): SecretRef {
  return {
    provider: "env",
    key
  };
}
