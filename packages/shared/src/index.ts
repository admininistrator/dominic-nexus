import { randomUUID } from "node:crypto";

export type Result<T, E = AppError> =
  | {
      ok: true;
      value: T;
    }
  | {
      ok: false;
      error: E;
    };

export type AsyncResult<T, E = AppError> = Promise<Result<T, E>>;

export type AppErrorCode =
  | "config.invalid"
  | "config.write_denied"
  | "config.write_failed"
  | "filesystem.permission_denied"
  | "filesystem.root_violation"
  | "permission.denied"
  | "tool.invalid_input"
  | "tool.invalid_output"
  | "tool.not_found"
  | "tool.permission_denied"
  | "tool.execution_failed"
  | "provider.permission_denied"
  | "provider.invalid_model_ref"
  | "provider.not_found"
  | "provider.execution_context_missing"
  | "provider.chat_unsupported"
  | "provider.model_listing_unsupported"
  | "provider.unsupported_model"
  | "provider.execution_failed"
  | "secret.invalid_ref"
  | "secret.read_denied"
  | "secret.unresolved"
  | "memory.invalid_model"
  | "memory.read_denied"
  | "memory.write_denied"
  | "network.invalid_request"
  | "shell.invalid_request"
  | "agent.invalid_input"
  | "agent.provider_not_found"
  | "agent.turn_cancelled"
  | "agent.turn_timed_out"
  | "session.invalid"
  | "session.not_found"
  | "session.write_failed"
  | "transcript.invalid"
  | "transcript.read_failed"
  | "transcript.write_failed"
  | "unexpected";

export interface AppErrorOptions {
  code: AppErrorCode;
  message: string;
  context?: Record<string, JsonValue>;
  cause?: unknown;
}

export interface SerializedAppError {
  name: string;
  code: AppErrorCode;
  message: string;
  context?: Record<string, JsonValue>;
}

export class AppError extends Error {
  readonly code: AppErrorCode;
  readonly context?: Record<string, JsonValue>;

  constructor(options: AppErrorOptions) {
    super(options.message);
    this.name = "AppError";
    this.code = options.code;

    if (options.context !== undefined) {
      this.context = redactJsonRecord(options.context);
    }

    if (options.cause !== undefined) {
      this.cause = options.cause;
    }
  }
}

export function ok<T>(value: T): Result<T> {
  return {
    ok: true,
    value
  };
}

export function err<E extends AppError>(error: E): Result<never, E> {
  return {
    ok: false,
    error
  };
}

export function isOk<T, E extends AppError>(result: Result<T, E>): result is { ok: true; value: T } {
  return result.ok;
}

export function isErr<T, E extends AppError>(result: Result<T, E>): result is { ok: false; error: E } {
  return !result.ok;
}

export type JsonPrimitive = string | number | boolean | null;

export type JsonValue =
  | JsonPrimitive
  | JsonValue[]
  | {
      [key: string]: JsonValue;
    };

export type JsonObject = {
  [key: string]: JsonValue;
};

export type ISODateTimeString = string;
export const REDACTED_PLACEHOLDER = "[redacted]";

const SENSITIVE_CONTEXT_KEY_PATTERN =
  /(authorization|credential|cookie|password|secret|token|api[_-]?key|private[_-]?key|access[_-]?key|refresh[_-]?key|^key$|[_-]key$|\bkey\b)/i;

function isSensitiveContextKey(key: string): boolean {
  return SENSITIVE_CONTEXT_KEY_PATTERN.test(key);
}

function redactJsonValue(key: string, value: JsonValue): JsonValue {
  if (isSensitiveContextKey(key)) {
    return REDACTED_PLACEHOLDER;
  }

  if (Array.isArray(value)) {
    return value.map((item) => redactJsonValue("", item));
  }

  if (value !== null && typeof value === "object") {
    return redactJsonRecord(value);
  }

  return value;
}

export function redactJsonRecord(record: Record<string, JsonValue>): Record<string, JsonValue> {
  return Object.fromEntries(Object.entries(record).map(([key, value]) => [key, redactJsonValue(key, value)]));
}

export function serializeAppError(error: unknown): SerializedAppError {
  if (error instanceof AppError) {
    const serialized: SerializedAppError = {
      name: error.name,
      code: error.code,
      message: error.message
    };

    if (error.context !== undefined) {
      serialized.context = redactJsonRecord(error.context);
    }

    return serialized;
  }

  return {
    name: error instanceof Error ? error.name : "UnknownError",
    code: "unexpected",
    message: "Unexpected error"
  };
}

export function toAppError(error: unknown, fallback: Omit<AppErrorOptions, "cause">): AppError {
  if (error instanceof AppError) {
    return error;
  }

  return new AppError({
    ...fallback,
    cause: error
  });
}

declare const brand: unique symbol;

export type Brand<TValue, TBrand extends string> = TValue & {
  readonly [brand]: TBrand;
};

export type SessionId = Brand<string, "SessionId">;
export type AgentId = Brand<string, "AgentId">;
export type ToolName = Brand<string, "ToolName">;
export type ProviderName = Brand<string, "ProviderName">;
export type ChannelId = Brand<string, "ChannelId">;
export type PluginId = Brand<string, "PluginId">;
export type EventId = Brand<string, "EventId">;

function createBrandedId<TId extends Brand<string, string>>(kind: string, value: string): TId {
  if (value.trim().length === 0) {
    throw new Error(`${kind} must be a non-empty string`);
  }

  return value as TId;
}

export function sessionId(value: string): SessionId {
  return createBrandedId<SessionId>("SessionId", value);
}

export function agentId(value: string): AgentId {
  return createBrandedId<AgentId>("AgentId", value);
}

export function toolName(value: string): ToolName {
  return createBrandedId<ToolName>("ToolName", value);
}

export function providerName(value: string): ProviderName {
  return createBrandedId<ProviderName>("ProviderName", value);
}

export function channelId(value: string): ChannelId {
  return createBrandedId<ChannelId>("ChannelId", value);
}

export function pluginId(value: string): PluginId {
  return createBrandedId<PluginId>("PluginId", value);
}

export function eventId(value: string): EventId {
  return createBrandedId<EventId>("EventId", value);
}

export interface Clock {
  now(): Date;
  nowIso(): ISODateTimeString;
}

export class SystemClock implements Clock {
  now(): Date {
    return new Date();
  }

  nowIso(): ISODateTimeString {
    return this.now().toISOString();
  }
}

export class FixedClock implements Clock {
  private readonly fixedDate: Date;

  constructor(value: Date | ISODateTimeString) {
    const date = value instanceof Date ? value : new Date(value);

    if (Number.isNaN(date.getTime())) {
      throw new Error("FixedClock value must be a valid date");
    }

    this.fixedDate = new Date(date.getTime());
  }

  now(): Date {
    return new Date(this.fixedDate.getTime());
  }

  nowIso(): ISODateTimeString {
    return this.fixedDate.toISOString();
  }
}

export interface IdGenerator {
  createSessionId(): SessionId;
  createEventId(): EventId;
}

export class RandomIdGenerator implements IdGenerator {
  createSessionId(): SessionId {
    return sessionId(`session-${randomUUID()}`);
  }

  createEventId(): EventId {
    return eventId(`event-${randomUUID()}`);
  }
}

export interface SequentialIdGeneratorOptions {
  sessionPrefix?: string;
  eventPrefix?: string;
  startAt?: number;
}

export class SequentialIdGenerator implements IdGenerator {
  private readonly sessionPrefix: string;
  private readonly eventPrefix: string;
  private nextSessionNumber: number;
  private nextEventNumber: number;

  constructor(options: SequentialIdGeneratorOptions = {}) {
    const startAt = options.startAt ?? 1;

    if (!Number.isInteger(startAt) || startAt < 0) {
      throw new Error("SequentialIdGenerator startAt must be a non-negative integer");
    }

    this.sessionPrefix = options.sessionPrefix ?? "session";
    this.eventPrefix = options.eventPrefix ?? "event";
    this.nextSessionNumber = startAt;
    this.nextEventNumber = startAt;
  }

  createSessionId(): SessionId {
    const id = sessionId(`${this.sessionPrefix}-${this.nextSessionNumber}`);
    this.nextSessionNumber += 1;
    return id;
  }

  createEventId(): EventId {
    const id = eventId(`${this.eventPrefix}-${this.nextEventNumber}`);
    this.nextEventNumber += 1;
    return id;
  }
}

export interface RuntimeUtilities {
  clock: Clock;
  idGenerator: IdGenerator;
}

export function createDefaultRuntimeUtilities(): RuntimeUtilities {
  return {
    clock: new SystemClock(),
    idGenerator: new RandomIdGenerator()
  };
}

export type SourcePackage =
  | "@dominic-nexus/audit"
  | "@dominic-nexus/channels"
  | "@dominic-nexus/config"
  | "@dominic-nexus/core"
  | "@dominic-nexus/logging"
  | "@dominic-nexus/memory"
  | "@dominic-nexus/permissions"
  | "@dominic-nexus/plugin-sdk"
  | "@dominic-nexus/providers"
  | "@dominic-nexus/secrets"
  | "@dominic-nexus/shared"
  | "@dominic-nexus/tools"
  | "@dominic-nexus/cli";

export const DOMAIN_EVENT_TYPES = [
  "lifecycle.runtime_started",
  "lifecycle.runtime_stopped",
  "lifecycle.runtime_failed",
  "permission.requested",
  "permission.decided",
  "provider.call_requested",
  "provider.call_succeeded",
  "provider.call_failed",
  "tool.execution_requested",
  "tool.execution_succeeded",
  "tool.execution_failed",
  "memory.read_requested",
  "memory.read_succeeded",
  "memory.read_failed",
  "memory.write_requested",
  "memory.write_succeeded",
  "memory.write_failed",
  "secret.read_requested",
  "secret.read_succeeded",
  "secret.read_denied",
  "session.created",
  "session.updated",
  "session.closed",
  "channel.message_received",
  "channel.message_sent",
  "channel.delivery_failed"
] as const;

export type DomainEventType = (typeof DOMAIN_EVENT_TYPES)[number];

export interface DomainEventPayloadMap {
  "lifecycle.runtime_started": JsonObject & {
    appName?: string;
    environment?: string;
  };
  "lifecycle.runtime_stopped": JsonObject & {
    reason?: string;
  };
  "lifecycle.runtime_failed": JsonObject & {
    errorCode?: AppErrorCode;
    errorMessage: string;
  };
  "permission.requested": JsonObject & {
    action: string;
    reason?: string;
    resource?: string;
  };
  "permission.decided": JsonObject & {
    action: string;
    allowed: boolean;
    policyName?: string;
    reason?: string;
    resource?: string;
  };
  "provider.call_requested": JsonObject & {
    messageCount?: number;
    model?: string;
    providerName: ProviderName;
  };
  "provider.call_succeeded": JsonObject & {
    messageCount?: number;
    model?: string;
    providerName: ProviderName;
  };
  "provider.call_failed": JsonObject & {
    errorCode?: AppErrorCode;
    errorMessage: string;
    model?: string;
    providerName: ProviderName;
  };
  "tool.execution_requested": JsonObject & {
    permissionActions?: string[];
    toolName: ToolName;
  };
  "tool.execution_succeeded": JsonObject & {
    toolName: ToolName;
  };
  "tool.execution_failed": JsonObject & {
    errorCode?: AppErrorCode;
    errorMessage: string;
    toolName: ToolName;
  };
  "memory.read_requested": JsonObject & {
    key?: string;
    storeName?: string;
  };
  "memory.read_succeeded": JsonObject & {
    key?: string;
    storeName?: string;
  };
  "memory.read_failed": JsonObject & {
    errorCode?: AppErrorCode;
    errorMessage: string;
    key?: string;
    storeName?: string;
  };
  "memory.write_requested": JsonObject & {
    key?: string;
    storeName?: string;
  };
  "memory.write_succeeded": JsonObject & {
    key?: string;
    storeName?: string;
  };
  "memory.write_failed": JsonObject & {
    errorCode?: AppErrorCode;
    errorMessage: string;
    key?: string;
    storeName?: string;
  };
  "secret.read_requested": JsonObject & {
    secretName: string;
  };
  "secret.read_succeeded": JsonObject & {
    secretName: string;
  };
  "secret.read_denied": JsonObject & {
    reason?: string;
    secretName: string;
  };
  "session.created": JsonObject & {
    agentId: AgentId;
  };
  "session.updated": JsonObject & {
    reason?: string;
  };
  "session.closed": JsonObject & {
    reason?: string;
  };
  "channel.message_received": JsonObject & {
    channelId: ChannelId;
    senderId?: string;
    threadId?: string;
  };
  "channel.message_sent": JsonObject & {
    channelId: ChannelId;
    threadId?: string;
  };
  "channel.delivery_failed": JsonObject & {
    channelId: ChannelId;
    errorCode?: AppErrorCode;
    errorMessage: string;
    threadId?: string;
  };
}

export interface DomainEvent<TType extends DomainEventType = DomainEventType> {
  type: TType;
  eventId: EventId;
  timestamp: ISODateTimeString;
  sourcePackage: SourcePackage;
  sessionId?: SessionId;
  payload: DomainEventPayloadMap[TType];
}

export interface CreateDomainEventOptions<TType extends DomainEventType> {
  type: TType;
  eventId: EventId;
  timestamp: ISODateTimeString;
  sourcePackage: SourcePackage;
  sessionId?: SessionId;
  payload: DomainEventPayloadMap[TType];
}

function isPlainJsonObject(value: object): boolean {
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function isJsonValueInternal(value: unknown, seen: Set<object>): value is JsonValue {
  if (value === null) {
    return true;
  }

  switch (typeof value) {
    case "string":
    case "boolean":
      return true;
    case "number":
      return Number.isFinite(value);
    case "object":
      if (seen.has(value)) {
        return false;
      }

      seen.add(value);

      if (Array.isArray(value)) {
        const isJsonArray = value.every((item) => isJsonValueInternal(item, seen));
        seen.delete(value);
        return isJsonArray;
      }

      if (!isPlainJsonObject(value)) {
        seen.delete(value);
        return false;
      }

      const isJsonObjectValue = Object.values(value).every((item) => isJsonValueInternal(item, seen));
      seen.delete(value);
      return isJsonObjectValue;
    default:
      return false;
  }
}

export function isJsonValue(value: unknown): value is JsonValue {
  return isJsonValueInternal(value, new Set<object>());
}

export function assertJsonValue(value: unknown, label = "value"): asserts value is JsonValue {
  if (!isJsonValue(value)) {
    throw new Error(`${label} must be JSON-safe`);
  }
}

export function isJsonObject(value: unknown): value is JsonObject {
  return value !== null && typeof value === "object" && !Array.isArray(value) && isJsonValue(value);
}

export function assertJsonObject(value: unknown, label = "value"): asserts value is JsonObject {
  if (!isJsonObject(value)) {
    throw new Error(`${label} must be a JSON-safe object`);
  }
}

export function createDomainEvent<TType extends DomainEventType>(
  options: CreateDomainEventOptions<TType>
): DomainEvent<TType> {
  assertJsonObject(options.payload, "event payload");

  const event: DomainEvent<TType> = {
    type: options.type,
    eventId: options.eventId,
    timestamp: options.timestamp,
    sourcePackage: options.sourcePackage,
    payload: options.payload
  };

  if (options.sessionId !== undefined) {
    event.sessionId = options.sessionId;
  }

  return event;
}

export type CreateDomainEventFromRuntimeOptions<TType extends DomainEventType> = Omit<
  CreateDomainEventOptions<TType>,
  "eventId" | "timestamp"
>;

export function createDomainEventFromRuntime<TType extends DomainEventType>(
  utilities: RuntimeUtilities,
  options: CreateDomainEventFromRuntimeOptions<TType>
): DomainEvent<TType> {
  return createDomainEvent({
    ...options,
    eventId: utilities.idGenerator.createEventId(),
    timestamp: utilities.clock.nowIso()
  });
}

export function assertNever(value: never): never {
  throw new Error(`Unexpected value: ${String(value)}`);
}
