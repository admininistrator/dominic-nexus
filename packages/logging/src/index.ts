import { REDACTED_PLACEHOLDER, type JsonValue } from "@dominic-nexus/shared";

export type LogLevel = "debug" | "info" | "warn" | "error";
export type LogContext = Record<string, unknown>;

export const REDACTED_LOG_VALUE = REDACTED_PLACEHOLDER;
export const CIRCULAR_LOG_VALUE = "[circular]";
export const UNSERIALIZABLE_LOG_VALUE = "[unserializable]";

const SENSITIVE_LOG_KEY_PATTERN =
  /(?:authorization|credential|cookie|password|secret|token|api[_-]?key|private[_-]?key|access[_-]?key|refresh[_-]?key|^key$|[_-]key$)/i;

export interface LogRecord {
  level: LogLevel;
  message: string;
  timestamp: string;
  context?: Record<string, JsonValue>;
}

export interface Logger {
  debug(message: string, context?: LogContext): void;
  info(message: string, context?: LogContext): void;
  warn(message: string, context?: LogContext): void;
  error(message: string, context?: LogContext): void;
}

export function isSensitiveLogKey(key: string): boolean {
  return SENSITIVE_LOG_KEY_PATTERN.test(key);
}

function redactLogValue(value: unknown, key: string, ancestors: WeakSet<object>): JsonValue {
  if (isSensitiveLogKey(key)) {
    return REDACTED_LOG_VALUE;
  }

  if (value === null || typeof value === "string" || typeof value === "boolean") {
    return value;
  }

  if (typeof value === "number") {
    return Number.isFinite(value) ? value : UNSERIALIZABLE_LOG_VALUE;
  }

  if (typeof value !== "object") {
    return UNSERIALIZABLE_LOG_VALUE;
  }

  if (ancestors.has(value)) {
    return CIRCULAR_LOG_VALUE;
  }

  ancestors.add(value);

  try {
    if (Array.isArray(value)) {
      return value.map((item) => redactLogValue(item, "", ancestors));
    }

    if (value instanceof Date) {
      return Number.isNaN(value.getTime()) ? UNSERIALIZABLE_LOG_VALUE : value.toISOString();
    }

    if (value instanceof Error) {
      return {
        name: value.name
      };
    }

    return Object.fromEntries(
      Object.entries(value).map(([nestedKey, nestedValue]) => [
        nestedKey,
        redactLogValue(nestedValue, nestedKey, ancestors)
      ])
    );
  } finally {
    ancestors.delete(value);
  }
}

export function redactLogContext(context: LogContext): Record<string, JsonValue> {
  const ancestors = new WeakSet<object>();

  return Object.fromEntries(
    Object.entries(context).map(([key, value]) => [key, redactLogValue(value, key, ancestors)])
  );
}

export function createConsoleLogger(): Logger {
  const write = (level: LogLevel, message: string, context?: LogContext) => {
    const record: LogRecord = {
      level,
      message,
      timestamp: new Date().toISOString()
    };

    if (context !== undefined) {
      record.context = redactLogContext(context);
    }

    const line = JSON.stringify(record);

    if (level === "error") {
      console.error(line);
      return;
    }

    if (level === "warn") {
      console.warn(line);
      return;
    }

    console.log(line);
  };

  return {
    debug: (message, context) => write("debug", message, context),
    info: (message, context) => write("info", message, context),
    warn: (message, context) => write("warn", message, context),
    error: (message, context) => write("error", message, context)
  };
}
