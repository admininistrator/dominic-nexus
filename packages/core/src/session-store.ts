import { mkdir, readdir, readFile, rename, writeFile } from "node:fs/promises";
import path from "node:path";
import type { AuditSink } from "@dominic-nexus/audit";
import type { PolicyEngine } from "@dominic-nexus/permissions";
import {
  authorizeFilesystemWrite,
  type FilesystemRootPolicy
} from "@dominic-nexus/tools";
import {
  agentId,
  AppError,
  err,
  isJsonObject,
  ok,
  sessionId,
  type AgentId,
  type Clock,
  type IdGenerator,
  type ISODateTimeString,
  type JsonObject,
  type Result,
  type SessionId
} from "@dominic-nexus/shared";

export interface SessionMetadata {
  sessionStartedAt: ISODateTimeString;
  lastInteractionAt: ISODateTimeString | null;
  updatedAt: ISODateTimeString;
  attributes: JsonObject;
}

export interface PersistedSession {
  id: SessionId;
  agentId: AgentId;
  metadata: SessionMetadata;
}

export interface CreateSessionOptions {
  agentId?: AgentId;
  attributes?: JsonObject;
}

export interface UpdateSessionOptions {
  attributes?: JsonObject;
  touchInteraction?: boolean;
}

export interface SessionStore {
  create(options?: CreateSessionOptions): Promise<Result<PersistedSession>>;
  list(): Promise<Result<PersistedSession[]>>;
  load(id: SessionId): Promise<Result<PersistedSession>>;
  update(id: SessionId, options: UpdateSessionOptions): Promise<Result<PersistedSession>>;
}

export interface SessionStoreAccess {
  mkdir(path: string): Promise<void>;
  readDirectory(path: string): Promise<string[]>;
  readFile(path: string): Promise<string>;
  rename(fromPath: string, toPath: string): Promise<void>;
  writeFile(path: string, content: string): Promise<void>;
}

export interface DirectorySessionStoreOptions {
  stateDirectory: string;
  filesystem: FilesystemRootPolicy;
  policy: PolicyEngine;
  audit: AuditSink;
  clock: Clock;
  idGenerator: IdGenerator;
  access?: SessionStoreAccess;
}

const SESSION_ID_PATTERN = /^[A-Za-z0-9._-]+$/u;

const DEFAULT_SESSION_STORE_ACCESS: SessionStoreAccess = {
  mkdir(dirPath) {
    return mkdir(dirPath, { recursive: true }).then(() => undefined);
  },
  readDirectory(dirPath) {
    return readdir(dirPath);
  },
  readFile(filePath) {
    return readFile(filePath, "utf8");
  },
  rename(fromPath, toPath) {
    return rename(fromPath, toPath);
  },
  writeFile(filePath, content) {
    return writeFile(filePath, content, "utf8");
  }
};

function sessionError(code: "session.invalid" | "session.not_found" | "session.write_failed", message: string, context?: JsonObject): Result<never> {
  return err(
    new AppError({
      code,
      message,
      ...(context !== undefined ? { context } : {})
    })
  );
}

function cloneJsonObject(value: JsonObject): JsonObject {
  return JSON.parse(JSON.stringify(value)) as JsonObject;
}

function validateSessionIdForPath(id: SessionId): Result<string> {
  const value = String(id);
  if (!SESSION_ID_PATTERN.test(value)) {
    return sessionError("session.invalid", "Session id contains characters that are not safe for filenames", {
      sessionId: value
    });
  }

  return ok(value);
}

function parseTimestamp(value: unknown, field: string): Result<ISODateTimeString> {
  if (typeof value !== "string" || value.trim().length === 0 || Number.isNaN(new Date(value).getTime())) {
    return sessionError("session.invalid", "Session metadata timestamp is invalid", {
      field
    });
  }

  return ok(value);
}

function parseNullableTimestamp(value: unknown): Result<ISODateTimeString | null> {
  if (value === null) {
    return ok(null);
  }

  return parseTimestamp(value, "metadata.lastInteractionAt");
}

function parseSessionMetadata(value: unknown): Result<SessionMetadata> {
  if (!isJsonObject(value)) {
    return sessionError("session.invalid", "Session metadata must be a JSON object");
  }

  const sessionStartedAt = parseTimestamp(value.sessionStartedAt, "metadata.sessionStartedAt");
  if (!sessionStartedAt.ok) {
    return sessionStartedAt;
  }

  const lastInteractionAt = parseNullableTimestamp(value.lastInteractionAt);
  if (!lastInteractionAt.ok) {
    return lastInteractionAt;
  }

  const updatedAt = parseTimestamp(value.updatedAt, "metadata.updatedAt");
  if (!updatedAt.ok) {
    return updatedAt;
  }

  if (!isJsonObject(value.attributes)) {
    return sessionError("session.invalid", "Session metadata attributes must be a JSON object", {
      field: "metadata.attributes"
    });
  }

  return ok({
    sessionStartedAt: sessionStartedAt.value,
    lastInteractionAt: lastInteractionAt.value,
    updatedAt: updatedAt.value,
    attributes: cloneJsonObject(value.attributes)
  });
}

function parsePersistedSession(value: unknown): Result<PersistedSession> {
  if (!isJsonObject(value)) {
    return sessionError("session.invalid", "Session file must contain a JSON object");
  }

  if (typeof value.id !== "string" || value.id.trim().length === 0) {
    return sessionError("session.invalid", "Session id must be a non-empty string", {
      field: "id"
    });
  }

  const safeId = validateSessionIdForPath(sessionId(value.id));
  if (!safeId.ok) {
    return safeId;
  }

  if (typeof value.agentId !== "string" || value.agentId.trim().length === 0) {
    return sessionError("session.invalid", "Session agentId must be a non-empty string", {
      field: "agentId"
    });
  }

  const metadata = parseSessionMetadata(value.metadata);
  if (!metadata.ok) {
    return metadata;
  }

  return ok({
    id: sessionId(value.id),
    agentId: agentId(value.agentId),
    metadata: metadata.value
  });
}

function serializeSession(session: PersistedSession): string {
  return `${JSON.stringify(session, null, 2)}\n`;
}

function isMissingFileError(error: unknown): boolean {
  return typeof error === "object" && error !== null && "code" in error && error.code === "ENOENT";
}

export class DirectorySessionStore implements SessionStore {
  private readonly access: SessionStoreAccess;

  constructor(private readonly options: DirectorySessionStoreOptions) {
    this.access = options.access ?? DEFAULT_SESSION_STORE_ACCESS;
  }

  async create(options: CreateSessionOptions = {}): Promise<Result<PersistedSession>> {
    const now = this.options.clock.nowIso();
    const session: PersistedSession = {
      id: this.options.idGenerator.createSessionId(),
      agentId: options.agentId ?? agentId("agent-default"),
      metadata: {
        sessionStartedAt: now,
        lastInteractionAt: null,
        updatedAt: now,
        attributes: cloneJsonObject(options.attributes ?? {})
      }
    };

    const written = await this.writeSession(session, "Create session metadata");
    if (!written.ok) {
      return written;
    }

    return ok(session);
  }

  async list(): Promise<Result<PersistedSession[]>> {
    const sessionsDirectory = this.getSessionsDirectoryPath();
    const resolved = await this.options.filesystem.resolvePath(sessionsDirectory, "read");
    if (!resolved.ok) {
      return resolved;
    }

    let fileNames: string[];
    try {
      fileNames = await this.access.readDirectory(resolved.value.normalizedPath);
    } catch (error) {
      if (isMissingFileError(error)) {
        return ok([]);
      }

      return sessionError("session.invalid", "Session directory could not be read", {
        path: resolved.value.normalizedPath,
        errorName: error instanceof Error ? error.name : "UnknownError"
      });
    }

    const sessions: PersistedSession[] = [];
    for (const fileName of fileNames.filter((name) => name.endsWith(".json")).sort()) {
      const id = sessionId(fileName.slice(0, -".json".length));
      const session = await this.load(id);
      if (session.ok) {
        sessions.push(session.value);
      }
    }

    sessions.sort((left, right) => right.metadata.updatedAt.localeCompare(left.metadata.updatedAt));
    return ok(sessions);
  }

  async load(id: SessionId): Promise<Result<PersistedSession>> {
    const sessionPath = this.getSessionFilePath(id);
    if (!sessionPath.ok) {
      return sessionPath;
    }

    const resolved = await this.options.filesystem.resolvePath(sessionPath.value, "read");
    if (!resolved.ok) {
      return resolved;
    }

    let raw: string;
    try {
      raw = await this.access.readFile(resolved.value.normalizedPath);
    } catch (error) {
      if (isMissingFileError(error)) {
        return sessionError("session.not_found", "Session metadata file was not found", {
          sessionId: id
        });
      }

      return sessionError("session.invalid", "Session metadata file could not be read", {
        sessionId: id,
        errorName: error instanceof Error ? error.name : "UnknownError"
      });
    }

    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch {
      return sessionError("session.invalid", "Session metadata file contains malformed JSON", {
        sessionId: id
      });
    }

    const session = parsePersistedSession(parsed);
    if (!session.ok) {
      return session;
    }

    if (session.value.id !== id) {
      return sessionError("session.invalid", "Session metadata id does not match the requested session", {
        requestedSessionId: id,
        storedSessionId: session.value.id
      });
    }

    return session;
  }

  async update(id: SessionId, options: UpdateSessionOptions): Promise<Result<PersistedSession>> {
    const current = await this.load(id);
    if (!current.ok) {
      return current;
    }

    const now = this.options.clock.nowIso();
    const metadata: SessionMetadata = {
      sessionStartedAt: current.value.metadata.sessionStartedAt,
      lastInteractionAt: options.touchInteraction === true ? now : current.value.metadata.lastInteractionAt,
      updatedAt: now,
      attributes: {
        ...cloneJsonObject(current.value.metadata.attributes),
        ...cloneJsonObject(options.attributes ?? {})
      }
    };
    const next: PersistedSession = {
      id: current.value.id,
      agentId: current.value.agentId,
      metadata
    };

    const written = await this.writeSession(next, "Update session metadata");
    if (!written.ok) {
      return written;
    }

    return ok(next);
  }

  private getSessionsDirectoryPath(): string {
    return path.join(this.options.stateDirectory, "sessions");
  }

  private getSessionFilePath(id: SessionId): Result<string> {
    const safeId = validateSessionIdForPath(id);
    if (!safeId.ok) {
      return safeId;
    }

    return ok(path.join(this.getSessionsDirectoryPath(), `${safeId.value}.json`));
  }

  private async writeSession(session: PersistedSession, reason: string): Promise<Result<void>> {
    const sessionPath = this.getSessionFilePath(session.id);
    if (!sessionPath.ok) {
      return sessionPath;
    }

    const authorization = await authorizeFilesystemWrite(this.options.filesystem, {
      path: sessionPath.value,
      policy: this.options.policy,
      audit: {
        audit: this.options.audit,
        clock: this.options.clock,
        idGenerator: this.options.idGenerator,
        sessionId: session.id
      },
      reason,
      metadata: {
        operation: "session.metadata.write",
        sessionId: session.id
      }
    });
    if (!authorization.ok) {
      return authorization;
    }

    const tempPath = `${authorization.value.normalizedPath}.tmp`;
    try {
      await this.access.mkdir(path.dirname(authorization.value.normalizedPath));
      await this.access.writeFile(tempPath, serializeSession(session));
      await this.access.rename(tempPath, authorization.value.normalizedPath);
    } catch (error) {
      return sessionError("session.write_failed", "Session metadata file could not be written", {
        sessionId: session.id,
        path: authorization.value.normalizedPath,
        errorName: error instanceof Error ? error.name : "UnknownError"
      });
    }

    return ok(undefined);
  }
}
