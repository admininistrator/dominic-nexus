import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { PermissionDecision, PermissionRequest, PolicyEngine } from "@dominic-nexus/permissions";
import { InMemoryStore } from "./index.js";

class RecordingPolicy implements PolicyEngine {
  readonly requests: PermissionRequest[] = [];

  constructor(private readonly decision: PermissionDecision = { allowed: true }) {}

  decide(request: PermissionRequest): PermissionDecision {
    this.requests.push(request);
    return this.decision;
  }
}

beforeEach(() => {
  vi.useFakeTimers();
  vi.setSystemTime(new Date("2026-01-02T03:04:05.000Z"));
});

afterEach(() => {
  vi.useRealTimers();
});

describe("InMemoryStore", () => {
  it("checks write/read permissions and searches records by namespace", async () => {
    const policy = new RecordingPolicy();
    const store = new InMemoryStore(policy);

    const first = await store.write({
      namespace: "notes",
      content: { text: "first" },
      metadata: { source: "test" }
    });
    await store.write({
      namespace: "other",
      content: { text: "second" }
    });

    const results = await store.search("notes");

    expect(first).toMatchObject({
      namespace: "notes",
      content: { text: "first" },
      metadata: { source: "test" },
      createdAt: "2026-01-02T03:04:05.000Z",
      updatedAt: "2026-01-02T03:04:05.000Z"
    });
    expect(first.id).toEqual(expect.any(String));
    expect(results).toEqual([first]);
    expect(policy.requests).toEqual([
      {
        action: "memory.write",
        reason: "Write memory record",
        resource: "notes"
      },
      {
        action: "memory.write",
        reason: "Write memory record",
        resource: "other"
      },
      {
        action: "memory.read",
        reason: "Search memory records",
        resource: "notes"
      }
    ]);
  });

  it("throws when memory.write permission is denied", async () => {
    const store = new InMemoryStore(new RecordingPolicy({ allowed: false, reason: "write denied" }));

    await expect(store.write({ namespace: "notes", content: "blocked" })).rejects.toThrow("write denied");
  });

  it("throws when memory.read permission is denied", async () => {
    const store = new InMemoryStore(new RecordingPolicy({ allowed: false, reason: "read denied" }));

    await expect(store.search("notes")).rejects.toThrow("read denied");
  });
});
