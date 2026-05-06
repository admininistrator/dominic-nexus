import { describe, expect, it } from "vitest";
import type { PermissionDecision, PermissionRequest, PolicyEngine } from "@dominic-nexus/permissions";
import { MockProvider } from "./index.js";

class RecordingPolicy implements PolicyEngine {
  readonly requests: PermissionRequest[] = [];

  constructor(private readonly decision: PermissionDecision = { allowed: true }) {}

  decide(request: PermissionRequest): PermissionDecision {
    this.requests.push(request);
    return this.decision;
  }
}

describe("MockProvider", () => {
  it("checks provider.call permission and echoes the last user message", async () => {
    const policy = new RecordingPolicy();
    const provider = new MockProvider(policy);

    const response = await provider.chat({
      messages: [
        { role: "system", content: "You are local." },
        { role: "user", content: "first" },
        { role: "assistant", content: "reply" },
        { role: "user", content: "second" }
      ],
      metadata: { requestId: "request-1" }
    });

    expect(response).toEqual({
      message: {
        role: "assistant",
        content: "second"
      }
    });
    expect(policy.requests).toEqual([
      {
        action: "provider.call",
        reason: "Call mock model provider",
        resource: "mock",
        metadata: { requestId: "request-1" }
      }
    ]);
  });

  it("throws when provider.call permission is denied", async () => {
    const provider = new MockProvider(new RecordingPolicy({ allowed: false, reason: "provider denied" }));

    await expect(provider.chat({ messages: [{ role: "user", content: "hello" }] })).rejects.toThrow(
      "provider denied"
    );
  });
});
