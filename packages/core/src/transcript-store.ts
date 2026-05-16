import { appendFile, mkdir, readFile } from "node:fs/promises";
import path from "node:path";
import type { AuditSink } from "@dominic-nexus/audit";
import type { PolicyEngine } from "@dominic-nexus/permissions";
import { authorizeFilesystemWrite, type FilesystemRootPolicy } from "@dominic-nexus/tools";
import {
  AppError,
  err,
  eventId,
  isJsonObject,
  isJsonValue,
  ok,
  sessionId,
  toolName,
  type Clock,
  type EventId,
  type IdGenerator,
  type ISODateTimeString,
  type JsonObject,
  type JsonValue,
  type Result,
  type SessionId,
  type ToolName
} from "@dominic-nexus/shared";

export type TranscriptEventType = "user" | "assistant" | "tool" | "lifecycle" | "error";

export interface TranscriptUserPayload extends JsonObject {
  content: string;
  metadata?: JsonObject;
}

export interface TranscriptAssistantPayload extends JsonObject {
  content: string;
  metadata?: JsonObject;
}

export type TranscriptToolPhase = "requested" | "succeeded" | "failed";

export interface TranscriptToolPayload extends JsonObject {
  toolName: ToolName;
  phase: TranscriptToolPhase;
  input?: JsonValue;
  output?: JsonValue;
  error?: JsonObject;
  metadata?: JsonObject;
}

export interface TranscriptLifecyclePayload extends JsonObject {
  name: string;
  metadata?: JsonObject;
}

export interface TranscriptErrorPayload extends JsonObject {
  errorName: string;
  message: string;
  code?: string;
  metadata?: JsonObject;
}

export interface TranscriptPayloadMap {
  user: TranscriptUserPayload;
  assistant: TranscriptAssistantPayload;
  tool: TranscriptToolPayload;
  lifecycle: TranscriptLifecyclePayload;
  error: TranscriptErrorPayload;
}

export type TranscriptEvent<TType extends TranscriptEventType = TranscriptEventType> = {
  [K in TranscriptEventType]: {
    type: K;
    eventId: EventId;
    sessionId: SessionId;
    timestamp: ISODateTimeString;
    payload: TranscriptPayloadMap[K];
  };
}[TType];

export type AppendTranscriptEventInput<TType extends TranscriptEventType = TranscriptEventType> = {
  [K in TranscriptEventType]: {
    type: K;
    payload: TranscriptPayloadMap[K];
  };
}[TType];

export interface MalformedTranscriptLine {
  lineNumber: number;
  reason: string;
  errorName?: string;
  length: number;
}

export interface TranscriptReadResult {
  sessionId: SessionId;
  events: TranscriptEvent[];
  malformedLines: MalformedTranscriptLine[];
}

export interface TranscriptStore {
  append<TType extends TranscriptEventType>(
    sessionId: SessionId,
    event: AppendTranscriptEventInput<TType>
  ): Promise<Result<TranscriptEvent<TType>>>;
  read(sessionId: SessionId): Promise<Result<TranscriptReadResult>>;
}

export interface TranscriptStoreAccess {
  appendFile(path: string, content: string): Promise<void>;
  mkdir(path: string): Promise<void>;
  readFile(path: string): Promise<string>;
}

export interface DirectoryTranscriptStoreOptions {
  stateDirectory: string;
  filesystem: FilesystemRootPolicy;
  policy: PolicyEngine;
  audit: AuditSink;
  clock: Clock;
  idGenerator: IdGenerator;
  access?: TranscriptStoreAccess;
}

const TRANSCRIPT_SESSION_ID_PATTERN = /^[A-Za-z0-9._-]+$/u;
const TRANSCRIPT_EVENT_TYPES = new Set<TranscriptEventType>(["user", "assistant", "tool", "lifecycle", "error"]);
const TRANSCRIPT_TOOL_PHASES = new Set<TranscriptToolPhase>(["requested", "succeeded", "failed"]);

const DEFAULT_TRANSCRIPT_STORE_ACCESS: TranscriptStoreAccess = {
  appendFile(filePath, content) {
    return appendFile(filePath, content, "utf8");
  },
  mkdir(dirPath) {
    return mkdir(dirPath, { recursive: true }).then(() => undefined);
  },
  readFile(filePath) {
    return readFile(filePath, "utf8");
  }
};

function transcriptError(
  code: "transcript.invalid" | "transcript.read_failed" | "transcript.write_failed",
  message: string,
  context?: JsonObject
): Result<never> {
  return err(
    new AppError({
      code,
      message,
      ...(context !== undefined ? { context } : {})
    })
  );
}

function validateSessionIdForTranscriptPath(id: SessionId): Result<string> {
  const value = String(id);
  if (!TRANSCRIPT_SESSION_ID_PATTERN.test(value)) {
    return transcriptError("transcript.invalid", "Session id contains characters that are not safe for filenames", {
      sessionId: value
    });
  }

  return ok(value);
}

function isMissingFileError(error: unknown): boolean {
  return typeof error === "object" && error !== null && "code" in error && error.code === "ENOENT";
}

function isValidTimestamp(value: unknown): value is ISODateTimeString {
  return typeof value === "string" && value.trim().length > 0 && !Number.isNaN(new Date(value).getTime());
}

function cloneJsonObject<T extends JsonObject>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

function validatePayload(type: TranscriptEventType, payload: unknown): Result<TranscriptPayloadMap[TranscriptEventType]> {
  if (!isJsonObject(payload)) {
    return transcriptError("transcript.invalid", "Transcript event payload must be a JSON object", {
      type
    });
  }

  switch (type) {
    case "user":
    case "assistant":
      if (typeof payload.content !== "string") {
        return transcriptError("transcript.invalid", "Transcript message content must be a string", {
          type,
          field: "payload.content"
        });
      }
      break;
    case "tool":
      if (typeof payload.toolName !== "string" || payload.toolName.trim().length === 0) {
        return transcriptError("transcript.invalid", "Transcript tool event must include a toolName", {
          field: "payload.toolName"
        });
      }

      if (typeof payload.phase !== "string" || !TRANSCRIPT_TOOL_PHASES.has(payload.phase as TranscriptToolPhase)) {
        return transcriptError("transcript.invalid", "Transcript tool event phase is invalid", {
          field: "payload.phase"
        });
      }
      break;
    case "lifecycle":
      if (typeof payload.name !== "string" || payload.name.trim().length === 0) {
        return transcriptError("transcript.invalid", "Transcript lifecycle event must include a name", {
          field: "payload.name"
        });
      }
      break;
    case "error":
      if (typeof payload.errorName !== "string" || payload.errorName.trim().length === 0) {
        return transcriptError("transcript.invalid", "Transcript error event must include an errorName", {
          field: "payload.errorName"
        });
      }

      if (typeof payload.message !== "string") {
        return transcriptError("transcript.invalid", "Transcript error event message must be a string", {
          field: "payload.message"
        });
      }

      if (payload.code !== undefined && typeof payload.code !== "string") {
        return transcriptError("transcript.invalid", "Transcript error event code must be a string when provided", {
          field: "payload.code"
        });
      }
      break;
  }

  return ok(cloneJsonObject(payload) as TranscriptPayloadMap[TranscriptEventType]);
}

function createTranscriptEvent<TType extends TranscriptEventType>(
  session: SessionId,
  input: AppendTranscriptEventInput<TType>,
  options: Pick<DirectoryTranscriptStoreOptions, "clock" | "idGenerator">
): Result<TranscriptEvent<TType>> {
  const payload = validatePayload(input.type, input.payload);
  if (!payload.ok) {
    return payload;
  }

  return ok({
    type: input.type,
    eventId: options.idGenerator.createEventId(),
    sessionId: session,
    timestamp: options.clock.nowIso(),
    payload: payload.value as TranscriptPayloadMap[TType]
  } as TranscriptEvent<TType>);
}

function parseTranscriptEvent(value: unknown, expectedSessionId: SessionId): Result<TranscriptEvent> {
  if (!isJsonObject(value)) {
    return transcriptError("transcript.invalid", "Transcript line must contain a JSON object");
  }

  if (typeof value.type !== "string" || !TRANSCRIPT_EVENT_TYPES.has(value.type as TranscriptEventType)) {
    return transcriptError("transcript.invalid", "Transcript event type is invalid", {
      field: "type"
    });
  }

  if (typeof value.eventId !== "string" || value.eventId.trim().length === 0) {
    return transcriptError("transcript.invalid", "Transcript eventId must be a non-empty string", {
      field: "eventId"
    });
  }

  if (typeof value.sessionId !== "string" || value.sessionId !== expectedSessionId) {
    return transcriptError("transcript.invalid", "Transcript event sessionId does not match the requested session", {
      field: "sessionId"
    });
  }

  if (!isValidTimestamp(value.timestamp)) {
    return transcriptError("transcript.invalid", "Transcript event timestamp is invalid", {
      field: "timestamp"
    });
  }

  const type = value.type as TranscriptEventType;
  const payload = validatePayload(type, value.payload);
  if (!payload.ok) {
    return payload;
  }

  return ok({
    type,
    eventId: eventId(value.eventId),
    sessionId: sessionId(value.sessionId),
    timestamp: value.timestamp,
    payload: payload.value
  } as TranscriptEvent);
}

function serializeTranscriptEvent(event: TranscriptEvent): string {
  return `${JSON.stringify(event)}\n`;
}

function malformedLine(lineNumber: number, line: string, reason: string, error?: unknown): MalformedTranscriptLine {
  const info: MalformedTranscriptLine = {
    lineNumber,
    reason,
    length: line.length
  };

  if (error !== undefined) {
    info.errorName = error instanceof Error ? error.name : "UnknownError";
  }

  return info;
}

export class DirectoryTranscriptStore implements TranscriptStore {
  private readonly access: TranscriptStoreAccess;
  private readonly writeQueues = new Map<string, Promise<void>>();

  constructor(private readonly options: DirectoryTranscriptStoreOptions) {
    this.access = options.access ?? DEFAULT_TRANSCRIPT_STORE_ACCESS;
  }

  async append<TType extends TranscriptEventType>(
    id: SessionId,
    input: AppendTranscriptEventInput<TType>
  ): Promise<Result<TranscriptEvent<TType>>> {
    const safeId = validateSessionIdForTranscriptPath(id);
    if (!safeId.ok) {
      return safeId;
    }

    const previous = this.writeQueues.get(safeId.value) ?? Promise.resolve();
    const operation = previous.then(() => this.appendNow(id, input));
    const queueItem = operation.then(
      () => undefined,
      () => undefined
    );
    this.writeQueues.set(safeId.value, queueItem);
    queueItem.finally(() => {
      if (this.writeQueues.get(safeId.value) === queueItem) {
        this.writeQueues.delete(safeId.value);
      }
    });

    return operation;
  }

  async read(id: SessionId): Promise<Result<TranscriptReadResult>> {
    const safeId = validateSessionIdForTranscriptPath(id);
    if (!safeId.ok) {
      return safeId;
    }

    await this.writeQueues.get(safeId.value);

    const transcriptPath = this.getTranscriptFilePath(id);
    if (!transcriptPath.ok) {
      return transcriptPath;
    }

    const resolved = await this.options.filesystem.resolvePath(transcriptPath.value, "read");
    if (!resolved.ok) {
      return resolved;
    }

    let raw: string;
    try {
      raw = await this.access.readFile(resolved.value.normalizedPath);
    } catch (error) {
      if (isMissingFileError(error)) {
        return ok({
          sessionId: id,
          events: [],
          malformedLines: []
        });
      }

      return transcriptError("transcript.read_failed", "Transcript file could not be read", {
        sessionId: id,
        errorName: error instanceof Error ? error.name : "UnknownError"
      });
    }

    const events: TranscriptEvent[] = [];
    const malformedLines: MalformedTranscriptLine[] = [];
    const lines = raw.split(/\r?\n/u);

    lines.forEach((line, index) => {
      if (line.length === 0 && index === lines.length - 1) {
        return;
      }

      let parsed: unknown;
      try {
        parsed = JSON.parse(line);
      } catch (error) {
        malformedLines.push(malformedLine(index + 1, line, "Malformed JSON", error));
        return;
      }

      if (!isJsonValue(parsed)) {
        malformedLines.push(malformedLine(index + 1, line, "Line is not JSON-safe"));
        return;
      }

      const event = parseTranscriptEvent(parsed, id);
      if (event.ok) {
        events.push(event.value);
      } else {
        malformedLines.push(malformedLine(index + 1, line, event.error.message, event.error));
      }
    });

    return ok({
      sessionId: id,
      events,
      malformedLines
    });
  }

  private getTranscriptsDirectoryPath(): string {
    return path.join(this.options.stateDirectory, "transcripts");
  }

  private getTranscriptFilePath(id: SessionId): Result<string> {
    const safeId = validateSessionIdForTranscriptPath(id);
    if (!safeId.ok) {
      return safeId;
    }

    return ok(path.join(this.getTranscriptsDirectoryPath(), `${safeId.value}.jsonl`));
  }

  private async appendNow<TType extends TranscriptEventType>(
    id: SessionId,
    input: AppendTranscriptEventInput<TType>
  ): Promise<Result<TranscriptEvent<TType>>> {
    const event = createTranscriptEvent(id, input, this.options);
    if (!event.ok) {
      return event;
    }

    const transcriptPath = this.getTranscriptFilePath(id);
    if (!transcriptPath.ok) {
      return transcriptPath;
    }

    const authorization = await authorizeFilesystemWrite(this.options.filesystem, {
      path: transcriptPath.value,
      policy: this.options.policy,
      audit: {
        audit: this.options.audit,
        clock: this.options.clock,
        idGenerator: this.options.idGenerator,
        sessionId: id
      },
      reason: "Append transcript event",
      metadata: {
        operation: "transcript.append",
        sessionId: id,
        eventType: event.value.type
      }
    });
    if (!authorization.ok) {
      return authorization;
    }

    try {
      await this.access.mkdir(path.dirname(authorization.value.normalizedPath));
      await this.access.appendFile(authorization.value.normalizedPath, serializeTranscriptEvent(event.value));
    } catch (error) {
      return transcriptError("transcript.write_failed", "Transcript event could not be appended", {
        sessionId: id,
        path: authorization.value.normalizedPath,
        errorName: error instanceof Error ? error.name : "UnknownError"
      });
    }

    return event;
  }
}
