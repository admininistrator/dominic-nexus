import type { JsonValue } from "@dominic-nexus/shared";

export type LogLevel = "debug" | "info" | "warn" | "error";

export interface LogRecord {
  level: LogLevel;
  message: string;
  timestamp: string;
  context?: Record<string, JsonValue>;
}

export interface Logger {
  debug(message: string, context?: Record<string, JsonValue>): void;
  info(message: string, context?: Record<string, JsonValue>): void;
  warn(message: string, context?: Record<string, JsonValue>): void;
  error(message: string, context?: Record<string, JsonValue>): void;
}

export function createConsoleLogger(): Logger {
  const write = (level: LogLevel, message: string, context?: Record<string, JsonValue>) => {
    const record: LogRecord = {
      level,
      message,
      timestamp: new Date().toISOString()
    };

    if (context !== undefined) {
      record.context = context;
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
