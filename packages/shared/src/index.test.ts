import { describe, expect, it } from "vitest";
import {
  agentId,
  AppError,
  assertJsonValue,
  channelId,
  createDefaultRuntimeUtilities,
  createDomainEvent,
  createDomainEventFromRuntime,
  DOMAIN_EVENT_TYPES,
  err,
  eventId,
  FixedClock,
  isJsonValue,
  isErr,
  isOk,
  ok,
  pluginId,
  providerName,
  RandomIdGenerator,
  REDACTED_PLACEHOLDER,
  serializeAppError,
  SequentialIdGenerator,
  sessionId,
  SystemClock,
  toolName
} from "./index.js";
import type { DomainEventPayloadMap } from "./index.js";

describe("branded ID helpers", () => {
  it("return deterministic string values", () => {
    expect(sessionId("session-123")).toBe("session-123");
    expect(agentId("agent-default")).toBe("agent-default");
    expect(toolName("echo")).toBe("echo");
    expect(providerName("mock")).toBe("mock");
    expect(channelId("local-console")).toBe("local-console");
    expect(pluginId("plugin-example")).toBe("plugin-example");
    expect(eventId("event-123")).toBe("event-123");
  });

  it("rejects empty IDs", () => {
    expect(() => sessionId("")).toThrow("SessionId must be a non-empty string");
    expect(() => toolName("   ")).toThrow("ToolName must be a non-empty string");
    expect(() => eventId("")).toThrow("EventId must be a non-empty string");
  });
});

describe("result helpers", () => {
  it("creates ok and err results with type guards", () => {
    const success = ok("value");
    const failure = err(
      new AppError({
        code: "unexpected",
        message: "Expected test failure"
      })
    );

    expect(isOk(success)).toBe(true);
    expect(isErr(success)).toBe(false);
    expect(isErr(failure)).toBe(true);
    expect(isOk(failure)).toBe(false);
  });
});

describe("runtime utilities", () => {
  it("provides production utilities backed by real time and random IDs", () => {
    const utilities = createDefaultRuntimeUtilities();

    expect(utilities.clock).toBeInstanceOf(SystemClock);
    expect(utilities.idGenerator).toBeInstanceOf(RandomIdGenerator);
    expect(utilities.clock.now()).toBeInstanceOf(Date);
    expect(utilities.clock.nowIso()).toMatch(/^\d{4}-\d{2}-\d{2}T/);
    expect(utilities.idGenerator.createSessionId()).toMatch(/^session-/);
    expect(utilities.idGenerator.createEventId()).toMatch(/^event-/);
  });

  it("provides fixed clocks and sequential IDs for deterministic tests", () => {
    const clock = new FixedClock("2026-05-07T00:00:00.000Z");
    const ids = new SequentialIdGenerator({
      sessionPrefix: "test-session",
      eventPrefix: "test-event",
      startAt: 7
    });

    expect(clock.nowIso()).toBe("2026-05-07T00:00:00.000Z");
    expect(clock.now()).not.toBe(clock.now());
    expect(ids.createSessionId()).toBe(sessionId("test-session-7"));
    expect(ids.createSessionId()).toBe(sessionId("test-session-8"));
    expect(ids.createEventId()).toBe(eventId("test-event-7"));
    expect(ids.createEventId()).toBe(eventId("test-event-8"));
  });

  it("rejects invalid deterministic utility configuration", () => {
    expect(() => new FixedClock("not-a-date")).toThrow("FixedClock value must be a valid date");
    expect(() => new SequentialIdGenerator({ startAt: -1 })).toThrow(
      "SequentialIdGenerator startAt must be a non-negative integer"
    );
  });
});

describe("domain events", () => {
  it("defines the shared event vocabulary by domain category", () => {
    expect(new Set(DOMAIN_EVENT_TYPES.map((type) => type.split(".")[0]))).toEqual(
      new Set(["lifecycle", "permission", "provider", "tool", "memory", "secret", "session", "channel"])
    );
  });

  it("creates session-scoped JSON-safe events for audit and Gateway consumers", () => {
    const event = createDomainEvent({
      type: "provider.call_requested",
      eventId: eventId("event-001"),
      timestamp: "2026-05-07T00:00:00.000Z",
      sourcePackage: "@dominic-nexus/providers",
      sessionId: sessionId("session-001"),
      payload: {
        providerName: providerName("mock"),
        model: "mock/default"
      }
    });

    expect(event).toEqual({
      type: "provider.call_requested",
      eventId: "event-001",
      timestamp: "2026-05-07T00:00:00.000Z",
      sourcePackage: "@dominic-nexus/providers",
      sessionId: "session-001",
      payload: {
        providerName: "mock",
        model: "mock/default"
      }
    });
    expect(JSON.parse(JSON.stringify(event))).toEqual(event);
  });

  it("allows non-session lifecycle events when no session applies", () => {
    const event = createDomainEvent({
      type: "lifecycle.runtime_started",
      eventId: eventId("event-runtime-started"),
      timestamp: "2026-05-07T00:00:00.000Z",
      sourcePackage: "@dominic-nexus/core",
      payload: {
        appName: "dominic-nexus",
        environment: "test"
      }
    });

    expect(event.sessionId).toBeUndefined();
    expect(event.payload).toEqual({
      appName: "dominic-nexus",
      environment: "test"
    });
  });

  it("creates events from deterministic runtime utilities", () => {
    const event = createDomainEventFromRuntime(
      {
        clock: new FixedClock("2026-05-07T00:00:00.000Z"),
        idGenerator: new SequentialIdGenerator()
      },
      {
        type: "session.created",
        sourcePackage: "@dominic-nexus/core",
        sessionId: sessionId("session-001"),
        payload: {
          agentId: agentId("agent-default")
        }
      }
    );

    expect(event).toEqual({
      type: "session.created",
      eventId: eventId("event-1"),
      timestamp: "2026-05-07T00:00:00.000Z",
      sourcePackage: "@dominic-nexus/core",
      sessionId: sessionId("session-001"),
      payload: {
        agentId: agentId("agent-default")
      }
    });
  });

  it("rejects event payloads with functions or non-JSON values", () => {
    const invalidPayloads: unknown[] = [
      {
        toolName: toolName("bad-tool"),
        callback: () => undefined
      },
      {
        timestamp: new Date("2026-05-07T00:00:00.000Z")
      },
      {
        missing: undefined
      },
      {
        invalidNumber: Number.NaN
      }
    ];

    for (const payload of invalidPayloads) {
      expect(() =>
        createDomainEvent({
          type: "tool.execution_requested",
          eventId: eventId("event-invalid"),
          timestamp: "2026-05-07T00:00:00.000Z",
          sourcePackage: "@dominic-nexus/tools",
          payload: payload as DomainEventPayloadMap["tool.execution_requested"]
        })
      ).toThrow("event payload must be a JSON-safe object");
    }
  });

  it("rejects circular JSON values without rejecting repeated object references", () => {
    const circular: Record<string, unknown> = {};
    circular.self = circular;

    expect(isJsonValue(circular)).toBe(false);

    const shared = {
      visible: "safe"
    };

    expect(() =>
      assertJsonValue({
        first: shared,
        second: shared
      })
    ).not.toThrow();
  });
});

describe("safe error serialization", () => {
  it("serializes AppError without stack traces and redacts sensitive context keys", () => {
    const error = new AppError({
      code: "provider.permission_denied",
      message: "Provider permission denied: mock",
      context: {
        providerName: "mock",
        token: "secret-token",
        private_key: "secret-private-key",
        access_key: "secret-access-key",
        refresh_key: "secret-refresh-key",
        signing_key: "secret-signing-key",
        key: "secret-key",
        nested: {
          apiKey: "secret-api-key",
          visible: "safe"
        }
      }
    });

    expect(serializeAppError(error)).toEqual({
      name: "AppError",
      code: "provider.permission_denied",
      message: "Provider permission denied: mock",
      context: {
        providerName: "mock",
        token: REDACTED_PLACEHOLDER,
        private_key: REDACTED_PLACEHOLDER,
        access_key: REDACTED_PLACEHOLDER,
        refresh_key: REDACTED_PLACEHOLDER,
        signing_key: REDACTED_PLACEHOLDER,
        key: REDACTED_PLACEHOLDER,
        nested: {
          apiKey: REDACTED_PLACEHOLDER,
          visible: "safe"
        }
      }
    });
  });

  it("does not expose raw unexpected error messages", () => {
    expect(serializeAppError(new Error("secret-value"))).toEqual({
      name: "Error",
      code: "unexpected",
      message: "Unexpected error"
    });
  });
});
