import { describe, expect, it } from "vitest";
import { REDACTED_LOG_VALUE } from "@dominic-nexus/logging";
import { eventId, FixedClock, SequentialIdGenerator, sessionId } from "@dominic-nexus/shared";
import {
  appendAuditEvent,
  createAuditEvent,
  createAuditEventFromRuntime,
  InMemoryAuditSink,
  redactAuditMetadata,
  serializeAuditEvent
} from "./index.js";

describe("audit event creation", () => {
  it("ignores append requests when audit runtime context is absent", async () => {
    await expect(
      appendAuditEvent(undefined, {
        sourcePackage: "@dominic-nexus/audit",
        action: "permission.decide",
        decision: "not_applicable",
        outcome: "failed"
      })
    ).resolves.toBeUndefined();
  });

  it("creates deterministic audit events from runtime utilities", () => {
    const event = createAuditEventFromRuntime(
      {
        clock: new FixedClock("2026-05-08T00:00:00.000Z"),
        idGenerator: new SequentialIdGenerator({
          eventPrefix: "audit-event",
          startAt: 4
        })
      },
      {
        sourcePackage: "@dominic-nexus/audit",
        sessionId: sessionId("session-001"),
        actor: {
          type: "local_operator",
          id: "operator-local"
        },
        action: "provider.call",
        decision: "allowed",
        resource: {
          type: "provider",
          id: "mock"
        },
        outcome: "requested",
        metadata: {
          model: "mock/default"
        }
      }
    );

    expect(event).toEqual({
      eventId: eventId("audit-event-4"),
      timestamp: "2026-05-08T00:00:00.000Z",
      sourcePackage: "@dominic-nexus/audit",
      sessionId: sessionId("session-001"),
      actor: {
        type: "local_operator",
        id: "operator-local"
      },
      action: "provider.call",
      decision: "allowed",
      resource: {
        type: "provider",
        id: "mock"
      },
      outcome: "requested",
      metadata: {
        model: "mock/default"
      }
    });
    expect(JSON.parse(JSON.stringify(event))).toEqual(event);
  });

  it("redacts sensitive metadata keys before storage or serialization", () => {
    const event = createAuditEvent({
      eventId: eventId("event-001"),
      timestamp: "2026-05-08T00:00:00.000Z",
      sourcePackage: "@dominic-nexus/secrets",
      action: "secret.read",
      decision: "denied",
      actor: {
        type: "system",
        metadata: {
          token: "actor-secret-token",
          visible: "actor-safe"
        }
      },
      resource: {
        type: "secret",
        id: "OPENAI_API_KEY",
        metadata: {
          apiKey: "resource-secret-key",
          visible: "resource-safe"
        }
      },
      metadata: {
        authorization: "Bearer secret-token",
        nested: {
          password: "secret-password",
          visible: "safe"
        }
      }
    });

    const serialized = JSON.stringify(event);

    expect(event.actor?.metadata).toEqual({
      token: REDACTED_LOG_VALUE,
      visible: "actor-safe"
    });
    expect(event.resource?.metadata).toEqual({
      apiKey: REDACTED_LOG_VALUE,
      visible: "resource-safe"
    });
    expect(event.metadata).toEqual({
      authorization: REDACTED_LOG_VALUE,
      nested: {
        password: REDACTED_LOG_VALUE,
        visible: "safe"
      }
    });
    expect(serialized).not.toContain("actor-secret-token");
    expect(serialized).not.toContain("resource-secret-key");
    expect(serialized).not.toContain("secret-token");
    expect(serialized).not.toContain("secret-password");
  });

  it("handles non-JSON and circular metadata safely", () => {
    const circular: Record<string, unknown> = {
      visible: "safe"
    };
    circular.self = circular;

    expect(
      redactAuditMetadata({
        circular,
        callback: () => undefined,
        invalidNumber: Number.NaN
      })
    ).toEqual({
      circular: {
        visible: "safe",
        self: "[circular]"
      },
      callback: "[unserializable]",
      invalidNumber: "[unserializable]"
    });
  });

  it("rejects empty actions and resource types", () => {
    expect(() =>
      createAuditEvent({
        eventId: eventId("event-empty-action"),
        timestamp: "2026-05-08T00:00:00.000Z",
        sourcePackage: "@dominic-nexus/audit",
        action: " ",
        decision: "pending"
      })
    ).toThrow("audit action must be a non-empty string");

    expect(() =>
      createAuditEvent({
        eventId: eventId("event-empty-resource"),
        timestamp: "2026-05-08T00:00:00.000Z",
        sourcePackage: "@dominic-nexus/audit",
        action: "tool.execute",
        decision: "pending",
        resource: {
          type: ""
        }
      })
    ).toThrow("audit resource type must be a non-empty string");
  });
});

describe("InMemoryAuditSink", () => {
  it("appends redacted immutable snapshots", async () => {
    const sink = new InMemoryAuditSink();
    const event = createAuditEvent({
      eventId: eventId("event-001"),
      timestamp: "2026-05-08T00:00:00.000Z",
      sourcePackage: "@dominic-nexus/tools",
      sessionId: sessionId("session-001"),
      action: "tool.execute",
      decision: "allowed",
      metadata: {
        token: "secret-token",
        visible: "safe"
      }
    });

    await sink.append(event);

    event.metadata = {
      visible: "mutated-after-append"
    };

    const firstSnapshot = sink.listEvents();
    expect(sink.count()).toBe(1);
    expect(firstSnapshot).toEqual([
      {
        eventId: eventId("event-001"),
        timestamp: "2026-05-08T00:00:00.000Z",
        sourcePackage: "@dominic-nexus/tools",
        sessionId: sessionId("session-001"),
        action: "tool.execute",
        decision: "allowed",
        metadata: {
          token: REDACTED_LOG_VALUE,
          visible: "safe"
        }
      }
    ]);

    (firstSnapshot[0] as typeof firstSnapshot[number]).metadata = {
      visible: "mutated-snapshot"
    };

    const storedAgain = sink.listEvents()[0];
    expect(storedAgain).toBeDefined();
    expect(serializeAuditEvent(storedAgain as NonNullable<typeof storedAgain>)).toMatchObject({
      metadata: {
        token: REDACTED_LOG_VALUE,
        visible: "safe"
      }
    });
  });
});
