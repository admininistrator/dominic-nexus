import { afterEach, describe, expect, it, vi } from "vitest";
import {
  CIRCULAR_LOG_VALUE,
  createConsoleLogger,
  isSensitiveLogKey,
  redactLogContext,
  REDACTED_LOG_VALUE,
  UNSERIALIZABLE_LOG_VALUE
} from "./index.js";

afterEach(() => {
  vi.restoreAllMocks();
});

describe("log redaction", () => {
  it("recognizes credential-shaped keys", () => {
    expect(isSensitiveLogKey("token")).toBe(true);
    expect(isSensitiveLogKey("apiKey")).toBe(true);
    expect(isSensitiveLogKey("private_key")).toBe(true);
    expect(isSensitiveLogKey("password")).toBe(true);
    expect(isSensitiveLogKey("authorization")).toBe(true);
    expect(isSensitiveLogKey("cookie")).toBe(true);
    expect(isSensitiveLogKey("credential")).toBe(true);
    expect(isSensitiveLogKey("messageLength")).toBe(false);
  });

  it("redacts nested sensitive values while preserving non-sensitive context", () => {
    expect(
      redactLogContext({
        providerName: "mock",
        messageCount: 2,
        token: "secret-token",
        request: {
          headers: {
            authorization: "Bearer secret",
            cookie: "session=secret",
            contentType: "application/json"
          },
          body: {
            visible: "safe",
            credentials: [
              {
                apiKey: "secret-api-key",
                label: "primary"
              }
            ]
          }
        }
      })
    ).toEqual({
      providerName: "mock",
      messageCount: 2,
      token: REDACTED_LOG_VALUE,
      request: {
        headers: {
          authorization: REDACTED_LOG_VALUE,
          cookie: REDACTED_LOG_VALUE,
          contentType: "application/json"
        },
        body: {
          visible: "safe",
          credentials: REDACTED_LOG_VALUE
        }
      }
    });
  });

  it("handles circular and non-JSON values safely", () => {
    const circular: Record<string, unknown> = {
      visible: "safe"
    };
    circular.self = circular;

    const shared = {
      value: "reused"
    };

    expect(
      redactLogContext({
        circular,
        first: shared,
        second: shared,
        missing: undefined,
        callback: () => undefined,
        id: BigInt(1),
        invalidNumber: Number.NaN
      })
    ).toEqual({
      circular: {
        visible: "safe",
        self: CIRCULAR_LOG_VALUE
      },
      first: {
        value: "reused"
      },
      second: {
        value: "reused"
      },
      missing: UNSERIALIZABLE_LOG_VALUE,
      callback: UNSERIALIZABLE_LOG_VALUE,
      id: UNSERIALIZABLE_LOG_VALUE,
      invalidNumber: UNSERIALIZABLE_LOG_VALUE
    });
  });
});

describe("createConsoleLogger", () => {
  it("writes redacted JSON log records", () => {
    const log = vi.spyOn(console, "log").mockImplementation(() => undefined);
    const logger = createConsoleLogger();

    logger.info("provider call", {
      providerName: "mock",
      token: "secret-token",
      nested: {
        password: "secret-password",
        safe: "visible"
      }
    });

    expect(log).toHaveBeenCalledOnce();
    const [line] = log.mock.calls[0] ?? [];
    expect(typeof line).toBe("string");

    const record = JSON.parse(line as string) as unknown;
    expect(record).toMatchObject({
      level: "info",
      message: "provider call",
      context: {
        providerName: "mock",
        token: REDACTED_LOG_VALUE,
        nested: {
          password: REDACTED_LOG_VALUE,
          safe: "visible"
        }
      }
    });
    expect(JSON.stringify(record)).not.toContain("secret-token");
    expect(JSON.stringify(record)).not.toContain("secret-password");
  });
});
