import { describe, expect, it } from "vitest";
import { ok } from "@dominic-nexus/shared";
import {
  createChannelSessionRoutingKey,
  createCliSessionRoutingKey,
  parseSessionRoutingKey,
  SessionTurnQueue,
  type SessionRoutingKey
} from "./session-routing.js";

async function flushMicrotasks(iterations = 20): Promise<void> {
  for (let index = 0; index < iterations; index += 1) {
    await Promise.resolve();
  }
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (error: unknown) => void;
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });

  return {
    promise,
    resolve,
    reject
  };
}

function routingKey(value: string): SessionRoutingKey {
  const key = createCliSessionRoutingKey({
    sessionId: value
  });

  if (!key.ok) {
    throw key.error;
  }

  return key.value;
}

describe("parseSessionRoutingKey", () => {
  it("rejects non-JSON routing key strings", () => {
    const result = parseSessionRoutingKey("not-json");

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe("session.invalid");
      expect(result.error.message).toBe("Session routing key must be valid JSON");
    }
  });

  it("rejects routing keys that parse to non-object values", () => {
    const result = parseSessionRoutingKey("[]");

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe("session.invalid");
      expect(result.error.message).toBe("Session routing key must decode to a JSON object");
    }
  });
});

describe("createChannelSessionRoutingKey", () => {
  it("rejects an empty channelId", () => {
    const result = createChannelSessionRoutingKey({
      channelId: "  "
    });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe("session.invalid");
      expect(result.error.context).toEqual({
        field: "channelId"
      });
    }
  });

  it("rejects empty optional routing fields", () => {
    const cases = [
      ["accountId", { accountId: "\t" }],
      ["roomId", { roomId: "   " }],
      ["threadId", { threadId: "\n" }],
      ["senderId", { senderId: "\r\n" }]
    ] as const;

    for (const [field, input] of cases) {
      const result = createChannelSessionRoutingKey({
        channelId: "local",
        ...input
      });

      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.error.code).toBe("session.invalid");
        expect(result.error.context).toEqual({
          field
        });
      }
    }
  });

  it("rejects explicit scope without the matching routing field", () => {
    const cases = [
      ["thread", { senderId: "sender-a" }, "threadId"],
      ["room", { senderId: "sender-a" }, "roomId"],
      ["sender", { roomId: "room-a" }, "senderId"]
    ] as const;

    for (const [scope, input, requiredField] of cases) {
      const result = createChannelSessionRoutingKey({
        channelId: "local",
        scope,
        ...input
      });

      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.error.code).toBe("session.invalid");
        expect(result.error.context).toEqual({
          scope,
          requiredField
        });
      }
    }
  });

  it("accepts explicit scope with the matching routing field", () => {
    const result = createChannelSessionRoutingKey({
      channelId: "local",
      scope: "thread",
      threadId: "thread-a",
      senderId: "sender-a"
    });

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(parseSessionRoutingKey(result.value)).toEqual(
        ok({
          version: 1,
          kind: "channel",
          scope: "thread",
          channelId: "local",
          threadId: "thread-a",
          senderId: "sender-a"
        })
      );
    }
  });
});

describe("SessionTurnQueue", () => {
  it("serializes operations for the same key", async () => {
    const queue = new SessionTurnQueue();
    const key = routingKey("session-a");
    const releaseFirst = deferred<void>();
    const operations: string[] = [];

    const first = queue.enqueue(key, async () => {
      operations.push("first:start");
      await releaseFirst.promise;
      operations.push("first:end");
      return "first";
    });
    await flushMicrotasks();

    const second = queue.enqueue(key, async () => {
      operations.push("second:start");
      operations.push("second:end");
      return "second";
    });
    await flushMicrotasks();

    expect(operations).toEqual(["first:start"]);

    releaseFirst.resolve();

    await expect(first).resolves.toBe("first");
    await expect(second).resolves.toBe("second");
    expect(operations).toEqual(["first:start", "first:end", "second:start", "second:end"]);
  });

  it("runs operations for different keys concurrently", async () => {
    const queue = new SessionTurnQueue();
    const releaseFirst = deferred<void>();
    const operations: string[] = [];

    const first = queue.enqueue(routingKey("session-a"), async () => {
      operations.push("first:start");
      await releaseFirst.promise;
      operations.push("first:end");
      return "first";
    });
    await flushMicrotasks();

    const second = queue.enqueue(routingKey("session-b"), async () => {
      operations.push("second:start");
      operations.push("second:end");
      return "second";
    });
    await flushMicrotasks();

    expect(operations).toEqual(["first:start", "second:start", "second:end"]);

    releaseFirst.resolve();

    await expect(first).resolves.toBe("first");
    await expect(second).resolves.toBe("second");
  });

  it("continues after a rejected operation", async () => {
    const queue = new SessionTurnQueue();
    const key = routingKey("session-a");
    const operations: string[] = [];

    const first = queue.enqueue(key, async () => {
      operations.push("first:start");
      throw new Error("expected failure");
    });
    const second = queue.enqueue(key, async () => {
      operations.push("second:start");
      return "second";
    });

    await expect(first).rejects.toThrow("expected failure");
    await expect(second).resolves.toBe("second");
    expect(operations).toEqual(["first:start", "second:start"]);
  });

  it("continues after a synchronously thrown operation", async () => {
    const queue = new SessionTurnQueue();
    const key = routingKey("session-a");
    const operations: string[] = [];

    const first = queue.enqueue(key, () => {
      operations.push("first:start");
      throw new Error("expected sync failure");
    });
    const second = queue.enqueue(key, async () => {
      operations.push("second:start");
      return "second";
    });

    await expect(first).rejects.toThrow("expected sync failure");
    await expect(second).resolves.toBe("second");
    expect(operations).toEqual(["first:start", "second:start"]);
  });

  it("returns the operation result", async () => {
    const queue = new SessionTurnQueue();

    await expect(
      queue.enqueue(routingKey("session-a"), async () => ({
        value: "operation-result"
      }))
    ).resolves.toEqual({
      value: "operation-result"
    });
  });

  it("preserves serialization for rapid same-key enqueues after settlement", async () => {
    const queue = new SessionTurnQueue();
    const key = routingKey("session-a");
    const releaseSecond = deferred<void>();
    const operations: string[] = [];

    const first = queue.enqueue(key, async () => {
      operations.push("first");
      return "first";
    });

    const second = first.then(() =>
      queue.enqueue(key, async () => {
        operations.push("second:start");
        await releaseSecond.promise;
        operations.push("second:end");
        return "second";
      })
    );

    await flushMicrotasks();

    const third = queue.enqueue(key, async () => {
      operations.push("third");
      return "third";
    });
    await flushMicrotasks();

    expect(operations).toEqual(["first", "second:start"]);

    releaseSecond.resolve();

    await expect(second).resolves.toBe("second");
    await expect(third).resolves.toBe("third");
    expect(operations).toEqual(["first", "second:start", "second:end", "third"]);
  });

  it("removes drained queue entries", async () => {
    const queue = new SessionTurnQueue();
    const key = routingKey("session-a");

    await expect(queue.enqueue(key, async () => "done")).resolves.toBe("done");
    await flushMicrotasks();

    const internals = queue as unknown as {
      queues: Map<string, Promise<void>>;
    };
    expect(internals.queues.size).toBe(0);
  });

  it("uses deterministic JSON-safe keys as map keys", async () => {
    const queue = new SessionTurnQueue();
    const key = routingKey("session-json");

    await expect(queue.enqueue(key, async () => parseSessionRoutingKey(key))).resolves.toEqual(
      ok({
        version: 1,
        kind: "cli",
        sessionId: "session-json"
      })
    );
  });
});
