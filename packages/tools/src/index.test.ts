import { describe, expect, it, vi } from "vitest";
import type { PermissionDecision, PermissionRequest, PolicyEngine } from "@dominic-nexus/permissions";
import { ToolRegistry, type ToolDefinition } from "./index.js";

class RecordingPolicy implements PolicyEngine {
  readonly requests: PermissionRequest[] = [];

  constructor(private readonly decision: PermissionDecision = { allowed: true }) {}

  decide(request: PermissionRequest): PermissionDecision {
    this.requests.push(request);
    return this.decision;
  }
}

describe("ToolRegistry", () => {
  it("registers and executes a tool after checking required permissions", async () => {
    const policy = new RecordingPolicy();
    const registry = new ToolRegistry();
    const execute = vi.fn((input: string) => input.toUpperCase());
    const tool: ToolDefinition<string, string> = {
      name: "uppercase",
      description: "Uppercase text",
      requiredPermissions: ["filesystem.read", "network.request"],
      execute
    };

    registry.register(tool);

    await expect(
      registry.execute<string, string>("uppercase", "hello", {
        policy,
        metadata: { traceId: "test-trace" }
      })
    ).resolves.toBe("HELLO");

    expect(execute).toHaveBeenCalledOnce();
    expect(policy.requests).toEqual([
      {
        action: "filesystem.read",
        reason: "Execute tool: uppercase",
        resource: "uppercase",
        metadata: { traceId: "test-trace" }
      },
      {
        action: "network.request",
        reason: "Execute tool: uppercase",
        resource: "uppercase",
        metadata: { traceId: "test-trace" }
      }
    ]);
  });

  it("throws and does not execute when permission is denied", async () => {
    const policy = new RecordingPolicy({ allowed: false, reason: "blocked" });
    const registry = new ToolRegistry();
    const execute = vi.fn();

    registry.register({
      name: "blocked-tool",
      description: "Blocked tool",
      requiredPermissions: ["shell.execute"],
      execute
    });

    await expect(registry.execute("blocked-tool", {}, { policy })).rejects.toThrow("blocked");

    expect(execute).not.toHaveBeenCalled();
    expect(policy.requests).toHaveLength(1);
    expect(policy.requests[0]?.action).toBe("shell.execute");
  });

  it("throws for unknown tools", async () => {
    const registry = new ToolRegistry();
    const policy = new RecordingPolicy();

    await expect(registry.execute("missing", {}, { policy })).rejects.toThrow("Tool not found: missing");
  });
});
