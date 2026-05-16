import {
  AppError,
  type Brand,
  err,
  isJsonObject,
  ok,
  type ChannelId,
  type JsonObject,
  type Result,
  type SessionId
} from "@dominic-nexus/shared";

export type SessionRoutingKey = Brand<string, "SessionRoutingKey">;

export type ChannelSessionRoutingScope = "thread" | "room" | "sender";

export interface CliSessionRoutingInput {
  sessionId: SessionId | string;
}

export interface ChannelSessionRoutingInput {
  channelId: ChannelId | string;
  accountId?: string;
  roomId?: string;
  threadId?: string;
  senderId?: string;
  scope?: ChannelSessionRoutingScope;
}

function sessionRoutingError(message: string, context?: JsonObject): Result<never> {
  return err(
    new AppError({
      code: "session.invalid",
      message,
      ...(context !== undefined ? { context } : {})
    })
  );
}

function normalizeRoutingComponent(value: string, field: string): Result<string> {
  const normalized = value.trim().normalize("NFC");

  if (normalized.length === 0) {
    return sessionRoutingError("Session routing component must be a non-empty string", {
      field
    });
  }

  return ok(normalized);
}

function createSessionRoutingKeyFromParts(parts: JsonObject): Result<SessionRoutingKey> {
  if (!isJsonObject(parts)) {
    return sessionRoutingError("Session routing key parts must be a JSON-safe object");
  }

  const key = JSON.stringify(parts);

  let roundTripped: unknown;
  try {
    roundTripped = JSON.parse(key);
  } catch {
    return sessionRoutingError("Session routing key must be JSON-safe");
  }

  if (!isJsonObject(roundTripped) || JSON.stringify(roundTripped) !== key) {
    return sessionRoutingError("Session routing key must be JSON-safe");
  }

  return ok(key as SessionRoutingKey);
}

function validateExplicitChannelScope(
  scope: ChannelSessionRoutingScope | undefined,
  normalizedOptionalFields: Record<string, string>
): Result<void> {
  if (scope === undefined) {
    return ok(undefined);
  }

  const requiredField = `${scope}Id`;
  if (normalizedOptionalFields[requiredField] === undefined) {
    return sessionRoutingError("Channel session routing scope requires the matching routing field", {
      scope,
      requiredField
    });
  }

  return ok(undefined);
}

export function parseSessionRoutingKey(key: SessionRoutingKey | string): Result<JsonObject> {
  let parsed: unknown;

  try {
    parsed = JSON.parse(String(key));
  } catch {
    return sessionRoutingError("Session routing key must be valid JSON");
  }

  if (!isJsonObject(parsed)) {
    return sessionRoutingError("Session routing key must decode to a JSON object");
  }

  return ok(parsed);
}

export function createCliSessionRoutingKey(input: CliSessionRoutingInput): Result<SessionRoutingKey> {
  const session = normalizeRoutingComponent(String(input.sessionId), "sessionId");
  if (!session.ok) {
    return session;
  }

  return createSessionRoutingKeyFromParts({
    version: 1,
    kind: "cli",
    sessionId: session.value
  });
}

export function createChannelSessionRoutingKey(input: ChannelSessionRoutingInput): Result<SessionRoutingKey> {
  const channel = normalizeRoutingComponent(String(input.channelId), "channelId");
  if (!channel.ok) {
    return channel;
  }

  const normalizedOptionalFields: Record<string, string> = {};
  const optionalFields = [
    ["accountId", input.accountId],
    ["roomId", input.roomId],
    ["threadId", input.threadId],
    ["senderId", input.senderId]
  ] as const;

  for (const [field, value] of optionalFields) {
    if (value === undefined) {
      continue;
    }

    const normalized = normalizeRoutingComponent(value, field);
    if (!normalized.ok) {
      return normalized;
    }

    normalizedOptionalFields[field] = normalized.value;
  }

  const scopeValidation = validateExplicitChannelScope(input.scope, normalizedOptionalFields);
  if (!scopeValidation.ok) {
    return scopeValidation;
  }

  return createSessionRoutingKeyFromParts({
    version: 1,
    kind: "channel",
    scope:
      input.scope ??
      (normalizedOptionalFields.threadId !== undefined
        ? "thread"
        : normalizedOptionalFields.roomId !== undefined
          ? "room"
          : "sender"),
    channelId: channel.value,
    ...normalizedOptionalFields
  });
}

export class SessionTurnQueue {
  private readonly queues = new Map<string, Promise<void>>();

  enqueue<T>(key: SessionRoutingKey, operation: () => Promise<T>): Promise<T> {
    const queueKey = String(key);
    const previous = this.queues.get(queueKey) ?? Promise.resolve();
    const current = previous.then(operation);
    const settled = current.then(
      () => undefined,
      () => undefined
    );

    settled.finally(() => {
      if (this.queues.get(queueKey) === settled) {
        this.queues.delete(queueKey);
      }
    });
    this.queues.set(queueKey, settled);

    return current;
  }
}
