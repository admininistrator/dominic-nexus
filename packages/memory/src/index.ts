import { randomUUID } from "node:crypto";
import { appendAuditEvent, type OptionalAuditRuntimeContext } from "@dominic-nexus/audit";
import {
  decidePermissionWithAudit,
  type PermissionDecision,
  type PermissionRequest,
  type PolicyEngine
} from "@dominic-nexus/permissions";
import {
  AppError,
  err,
  isJsonObject,
  isJsonValue,
  ok,
  toAppError,
  type Brand,
  type Clock,
  type EventId,
  type ISODateTimeString,
  type JsonObject,
  type JsonValue,
  type Result,
  type SessionId
} from "@dominic-nexus/shared";

export type MemoryRecordId = Brand<string, "MemoryRecordId">;
export type MemoryNamespace = Brand<string, "MemoryNamespace">;
export type MemoryRootPath = Brand<string, "MemoryRootPath">;
export type DailyMemoryNoteDate = Brand<string, "DailyMemoryNoteDate">;

export type MemoryRecordKind = "note" | "fact" | "preference" | "summary" | "task" | "daily-note";
export type MemoryRecordSource = "manual" | "agent" | "tool" | "import" | "system";
export type MemoryPersistenceFormat = "markdown";

export interface MemoryRecordProvenance {
  /**
   * Optional provenance link only. Durable memory records are not transcript
   * events and must not be used as a session transcript store.
   */
  sessionId?: SessionId;
  transcriptEventId?: EventId;
  source?: MemoryRecordSource;
}

export interface MemoryRecordTimestamps {
  createdAt: ISODateTimeString;
  updatedAt: ISODateTimeString;
}

export interface DurableMemoryFileLayout {
  format: MemoryPersistenceFormat;
  rootRecordFileName: "MEMORY.md";
  dailyNotesDirectory: "memory";
  dailyNoteFilePattern: "YYYY-MM-DD.md";
}

export interface MemoryWriteApprovalExpectation {
  requiredPermissionActions: readonly ["memory.write", "filesystem.write"];
  auditAction: "memory.write";
  rootBounded: true;
  contentExcludedFromAudit: true;
  durableStoreWritesRequireFilesystemWrite: true;
}

export interface MemoryRoot {
  /**
   * Configured root for future durable stores. This value is not an authorized
   * filesystem path by itself; durable stores must pass every derived read or
   * write through an injected root-bounded authorizer before touching disk.
   */
  rootPath: MemoryRootPath;
  defaultNamespace: MemoryNamespace;
  layout: DurableMemoryFileLayout;
  writeApproval: MemoryWriteApprovalExpectation;
}

export interface MemoryRootInput {
  rootPath: string;
  defaultNamespace?: string | MemoryNamespace;
}

export interface MemoryRecord {
  id: MemoryRecordId;
  namespace: MemoryNamespace;
  content: JsonValue;
  createdAt: ISODateTimeString;
  updatedAt: ISODateTimeString;
  kind?: MemoryRecordKind;
  metadata?: JsonObject;
  provenance?: MemoryRecordProvenance;
}

export interface MemoryRecordWriteInput {
  namespace: string | MemoryNamespace;
  content: JsonValue;
  kind?: MemoryRecordKind;
  metadata?: JsonObject;
  provenance?: MemoryRecordProvenance;
}

export interface DailyMemoryRecordWriteInput extends MemoryRecordWriteInput {
  /**
   * YYYY-MM-DD date scope for the daily note. When omitted, the store derives
   * the date from the injected clock or audit clock.
   */
  date?: string | DailyMemoryNoteDate;
}

export interface NormalizedMemoryRecordWriteInput {
  namespace: MemoryNamespace;
  content: JsonValue;
  kind?: MemoryRecordKind;
  metadata?: JsonObject;
  provenance?: MemoryRecordProvenance;
}

export interface MemoryStore {
  /**
   * Store a durable memory record. Session transcript events remain owned by
   * the core transcript store; a memory record may only carry optional
   * provenance links back to session or transcript identifiers.
   */
  write(record: MemoryRecordWriteInput): Promise<MemoryRecord>;
  /**
   * Return records whose namespace exactly equals the requested namespace.
   * Prefix or full-text search can be added by a later store-specific contract.
   * Single-record lookup by id is intentionally deferred until the Markdown
   * store needs a stable on-disk index.
   */
  search(namespace: string | MemoryNamespace): Promise<MemoryRecord[]>;
}

export type MemoryFileOperation = "read" | "append" | "replace" | "delete";

export interface MemoryFileAuthorizationRequest {
  root: MemoryRoot;
  operation: MemoryFileOperation;
  /**
   * Store-relative path such as MEMORY.md or memory/2026-05-15.md. It must be
   * resolved by the injected authorizer, not concatenated directly with rootPath.
   */
  relativePath: string;
  reason: string;
  metadata: JsonObject;
}

export interface MemoryFileAuthorization {
  normalizedPath: string;
  matchedRoot: string;
}

export type MemoryFileAuthorizer = (
  request: MemoryFileAuthorizationRequest
) => Result<MemoryFileAuthorization> | Promise<Result<MemoryFileAuthorization>>;

export interface CreateMemoryRecordOptions {
  id?: string | MemoryRecordId;
  input: MemoryRecordWriteInput;
  clock?: Clock;
  timestamp?: ISODateTimeString;
}

export interface InMemoryStoreOptions {
  clock?: Clock;
  createRecordId?: () => MemoryRecordId;
}

export interface MarkdownMemoryFileAccess {
  /**
   * Return undefined when the file does not exist. Other read failures should
   * throw an AppError or another safe error that does not include file content.
   */
  readText(path: string): Promise<string | undefined> | string | undefined;
  appendText(path: string, content: string): Promise<void> | void;
  replaceText(path: string, content: string): Promise<void> | void;
}

export interface MarkdownMemoryStoreOptions {
  root: MemoryRoot;
  policy: PolicyEngine;
  authorizer: MemoryFileAuthorizer;
  fileAccess: MarkdownMemoryFileAccess;
  auditContext?: OptionalAuditRuntimeContext;
  clock?: Clock;
  createRecordId?: () => MemoryRecordId;
}

export interface DailyMemoryNoteReadOptions {
  limit?: number;
}

export interface DailyMemoryNoteSearchOptions {
  namespace: string | MemoryNamespace;
  startDate: string | DailyMemoryNoteDate;
  endDate: string | DailyMemoryNoteDate;
  limit?: number;
}

export const DEFAULT_MEMORY_NAMESPACE = "default" as MemoryNamespace;

export const DURABLE_MEMORY_FILE_LAYOUT: DurableMemoryFileLayout = {
  format: "markdown",
  rootRecordFileName: "MEMORY.md",
  dailyNotesDirectory: "memory",
  dailyNoteFilePattern: "YYYY-MM-DD.md"
};

export const DURABLE_MEMORY_WRITE_APPROVAL: MemoryWriteApprovalExpectation = {
  requiredPermissionActions: ["memory.write", "filesystem.write"],
  auditAction: "memory.write",
  rootBounded: true,
  contentExcludedFromAudit: true,
  durableStoreWritesRequireFilesystemWrite: true
};

const MEMORY_NAMESPACE_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]*(\/[A-Za-z0-9][A-Za-z0-9._-]*)*$/u;
const MEMORY_RECORD_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]*$/u;
const MEMORY_RECORD_KINDS = new Set<MemoryRecordKind>(["note", "fact", "preference", "summary", "task", "daily-note"]);
const MEMORY_RECORD_SOURCES = new Set<MemoryRecordSource>(["manual", "agent", "tool", "import", "system"]);
const MAX_MEMORY_NAMESPACE_LENGTH = 160;
const MAX_MEMORY_NAMESPACE_SEGMENT_LENGTH = 64;
const MAX_MEMORY_RECORD_ID_LENGTH = 128;
const DAILY_MEMORY_NOTE_DATE_PATTERN = /^\d{4}-\d{2}-\d{2}$/u;
const DAILY_MEMORY_NOTE_DEFAULT_SEARCH_LIMIT = 50;
const DAILY_MEMORY_NOTE_MAX_SEARCH_LIMIT = 100;
const DAILY_MEMORY_NOTE_MAX_SEARCH_DAYS = 31;
const MILLISECONDS_PER_DAY = 24 * 60 * 60 * 1000;
const MARKDOWN_MEMORY_RECORD_START = "<!-- dominic-nexus-memory-record:v1 -->";
const MARKDOWN_MEMORY_RECORD_END = "<!-- /dominic-nexus-memory-record -->";

function memoryInvalid(message: string, context?: JsonObject): Result<never> {
  const options =
    context === undefined
      ? {
          code: "memory.invalid_model" as const,
          message
        }
      : {
          code: "memory.invalid_model" as const,
          message,
          context
        };

  return err(new AppError(options));
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function containsNulByte(value: string): boolean {
  return value.includes("\0");
}

function safeErrorName(error: unknown): string {
  return error instanceof Error ? error.name : "UnknownError";
}

function isAuthorizationDenied(error: AppError): boolean {
  return error.code === "filesystem.permission_denied" || error.code === "filesystem.root_violation";
}

export function memoryRecordId(value: string): MemoryRecordId {
  const normalized = normalizeMemoryRecordId(value);

  if (!normalized.ok) {
    throw normalized.error;
  }

  return normalized.value;
}

export function memoryNamespace(value: string): MemoryNamespace {
  const normalized = normalizeMemoryNamespace(value);

  if (!normalized.ok) {
    throw normalized.error;
  }

  return normalized.value;
}

export function memoryRootPath(value: string): MemoryRootPath {
  const normalized = normalizeMemoryRootPath(value);

  if (!normalized.ok) {
    throw normalized.error;
  }

  return normalized.value;
}

export function dailyMemoryNoteDate(value: string): DailyMemoryNoteDate {
  const normalized = normalizeDailyMemoryNoteDate(value);

  if (!normalized.ok) {
    throw normalized.error;
  }

  return normalized.value;
}

export function normalizeMemoryRecordId(value: unknown): Result<MemoryRecordId> {
  if (typeof value !== "string" || value.trim().length === 0) {
    return memoryInvalid("Memory record id must be a non-empty string", {
      field: "id"
    });
  }

  const normalized = value.trim();
  if (
    normalized.length > MAX_MEMORY_RECORD_ID_LENGTH ||
    containsNulByte(normalized) ||
    normalized.includes("/") ||
    normalized.includes("\\") ||
    !MEMORY_RECORD_ID_PATTERN.test(normalized)
  ) {
    return memoryInvalid("Memory record id contains invalid characters", {
      field: "id"
    });
  }

  return ok(normalized as MemoryRecordId);
}

export function normalizeMemoryNamespace(value: unknown): Result<MemoryNamespace> {
  if (typeof value !== "string" || value.trim().length === 0) {
    return memoryInvalid("Memory namespace must be a non-empty logical path", {
      field: "namespace"
    });
  }

  const normalized = value.trim();
  if (
    normalized.length > MAX_MEMORY_NAMESPACE_LENGTH ||
    containsNulByte(normalized) ||
    normalized.includes("\\") ||
    normalized.includes("//") ||
    !MEMORY_NAMESPACE_PATTERN.test(normalized)
  ) {
    return memoryInvalid("Memory namespace contains invalid path segments", {
      field: "namespace",
      namespace: normalized
    });
  }

  for (const segment of normalized.split("/")) {
    if (segment === "." || segment === ".." || segment.length > MAX_MEMORY_NAMESPACE_SEGMENT_LENGTH) {
      return memoryInvalid("Memory namespace contains invalid path segments", {
        field: "namespace",
        namespace: normalized
      });
    }
  }

  return ok(normalized as MemoryNamespace);
}

export function normalizeMemoryRootPath(value: unknown): Result<MemoryRootPath> {
  if (typeof value !== "string" || value.trim().length === 0) {
    return memoryInvalid("Memory root path must be a non-empty string", {
      field: "rootPath"
    });
  }

  const normalized = value.trim();
  if (containsNulByte(normalized)) {
    return memoryInvalid("Memory root path must not contain NUL bytes", {
      field: "rootPath"
    });
  }

  return ok(normalized as MemoryRootPath);
}

export function normalizeDailyMemoryNoteDate(value: unknown): Result<DailyMemoryNoteDate> {
  if (typeof value !== "string" || value.trim().length === 0) {
    return memoryInvalid("Daily memory note date must be a non-empty YYYY-MM-DD string", {
      field: "date"
    });
  }

  const normalized = value.trim();
  if (!DAILY_MEMORY_NOTE_DATE_PATTERN.test(normalized) || normalized.startsWith("0000")) {
    return memoryInvalid("Daily memory note date must use YYYY-MM-DD format", {
      field: "date",
      date: normalized
    });
  }

  const parsed = new Date(`${normalized}T00:00:00.000Z`);
  if (Number.isNaN(parsed.getTime()) || parsed.toISOString().slice(0, 10) !== normalized) {
    return memoryInvalid("Daily memory note date must be a valid calendar date", {
      field: "date",
      date: normalized
    });
  }

  return ok(normalized as DailyMemoryNoteDate);
}

export function createDailyMemoryNoteDate(clock?: Clock): DailyMemoryNoteDate {
  return dailyMemoryNoteDate((clock?.nowIso() ?? new Date().toISOString()).slice(0, 10));
}

export function createDailyMemoryNoteRelativePath(
  root: MemoryRoot,
  date: string | DailyMemoryNoteDate
): Result<string> {
  const normalizedDate = normalizeDailyMemoryNoteDate(date);
  if (!normalizedDate.ok) {
    return normalizedDate;
  }

  return ok(`${root.layout.dailyNotesDirectory}/${normalizedDate.value}.md`);
}

function dailyMemoryNoteDateToUtcTime(date: DailyMemoryNoteDate): number {
  return new Date(`${date}T00:00:00.000Z`).getTime();
}

function normalizeDailyMemoryNoteLimit(value: unknown): Result<number> {
  if (value === undefined) {
    return ok(DAILY_MEMORY_NOTE_DEFAULT_SEARCH_LIMIT);
  }

  if (
    typeof value !== "number" ||
    !Number.isInteger(value) ||
    value <= 0 ||
    value > DAILY_MEMORY_NOTE_MAX_SEARCH_LIMIT
  ) {
    return memoryInvalid("Daily memory note search limit must be an integer within bounds", {
      field: "limit",
      max: DAILY_MEMORY_NOTE_MAX_SEARCH_LIMIT
    });
  }

  return ok(value);
}

function createDailyMemoryNoteDateRange(
  startDate: string | DailyMemoryNoteDate,
  endDate: string | DailyMemoryNoteDate
): Result<DailyMemoryNoteDate[]> {
  const normalizedStartDate = normalizeDailyMemoryNoteDate(startDate);
  if (!normalizedStartDate.ok) {
    return normalizedStartDate;
  }

  const normalizedEndDate = normalizeDailyMemoryNoteDate(endDate);
  if (!normalizedEndDate.ok) {
    return normalizedEndDate;
  }

  const startTime = dailyMemoryNoteDateToUtcTime(normalizedStartDate.value);
  const endTime = dailyMemoryNoteDateToUtcTime(normalizedEndDate.value);
  if (endTime < startTime) {
    return memoryInvalid("Daily memory note endDate must be on or after startDate", {
      field: "endDate",
      startDate: normalizedStartDate.value,
      endDate: normalizedEndDate.value
    });
  }

  const dayCount = Math.floor((endTime - startTime) / MILLISECONDS_PER_DAY) + 1;
  if (dayCount > DAILY_MEMORY_NOTE_MAX_SEARCH_DAYS) {
    return memoryInvalid("Daily memory note search range is too large", {
      field: "dateRange",
      maxDays: DAILY_MEMORY_NOTE_MAX_SEARCH_DAYS
    });
  }

  const dates: DailyMemoryNoteDate[] = [];
  for (let time = startTime; time <= endTime; time += MILLISECONDS_PER_DAY) {
    dates.push(dailyMemoryNoteDate(new Date(time).toISOString().slice(0, 10)));
  }

  return ok(dates);
}

function normalizeMemoryRecordKind(value: unknown): Result<MemoryRecordKind | undefined> {
  if (value === undefined) {
    return ok(undefined);
  }

  if (typeof value !== "string" || !MEMORY_RECORD_KINDS.has(value as MemoryRecordKind)) {
    return memoryInvalid("Memory record kind is not supported", {
      field: "kind"
    });
  }

  return ok(value as MemoryRecordKind);
}

function normalizeMemoryRecordSource(value: unknown): Result<MemoryRecordSource | undefined> {
  if (value === undefined) {
    return ok(undefined);
  }

  if (typeof value !== "string" || !MEMORY_RECORD_SOURCES.has(value as MemoryRecordSource)) {
    return memoryInvalid("Memory record provenance source is not supported", {
      field: "provenance.source"
    });
  }

  return ok(value as MemoryRecordSource);
}

function normalizeMemoryRecordProvenance(value: unknown): Result<MemoryRecordProvenance | undefined> {
  if (value === undefined) {
    return ok(undefined);
  }

  if (!isRecord(value)) {
    return memoryInvalid("Memory record provenance must be an object", {
      field: "provenance"
    });
  }

  const source = normalizeMemoryRecordSource(value.source);
  if (!source.ok) {
    return source;
  }

  const provenance: MemoryRecordProvenance = {};

  if (value.sessionId !== undefined) {
    if (typeof value.sessionId !== "string" || value.sessionId.trim().length === 0 || containsNulByte(value.sessionId)) {
      return memoryInvalid("Memory record provenance sessionId must be a non-empty string", {
        field: "provenance.sessionId"
      });
    }

    provenance.sessionId = value.sessionId as SessionId;
  }

  if (value.transcriptEventId !== undefined) {
    if (
      typeof value.transcriptEventId !== "string" ||
      value.transcriptEventId.trim().length === 0 ||
      containsNulByte(value.transcriptEventId)
    ) {
      return memoryInvalid("Memory record provenance transcriptEventId must be a non-empty string", {
        field: "provenance.transcriptEventId"
      });
    }

    provenance.transcriptEventId = value.transcriptEventId as EventId;
  }

  if (source.value !== undefined) {
    provenance.source = source.value;
  }

  return ok(provenance);
}

export function normalizeMemoryRecordWriteInput(value: unknown): Result<NormalizedMemoryRecordWriteInput> {
  if (!isRecord(value)) {
    return memoryInvalid("Memory record write input must be an object");
  }

  const namespace = normalizeMemoryNamespace(value.namespace);
  if (!namespace.ok) {
    return namespace;
  }

  if (!("content" in value) || !isJsonValue(value.content)) {
    return memoryInvalid("Memory record content must be JSON-safe", {
      field: "content"
    });
  }

  const kind = normalizeMemoryRecordKind(value.kind);
  if (!kind.ok) {
    return kind;
  }

  if (value.metadata !== undefined && !isJsonObject(value.metadata)) {
    return memoryInvalid("Memory record metadata must be a JSON object", {
      field: "metadata"
    });
  }

  const provenance = normalizeMemoryRecordProvenance(value.provenance);
  if (!provenance.ok) {
    return provenance;
  }

  const normalized: NormalizedMemoryRecordWriteInput = {
    namespace: namespace.value,
    content: value.content
  };

  if (kind.value !== undefined) {
    normalized.kind = kind.value;
  }

  if (value.metadata !== undefined) {
    normalized.metadata = value.metadata;
  }

  if (provenance.value !== undefined) {
    normalized.provenance = provenance.value;
  }

  return ok(normalized);
}

export function createMemoryRoot(input: MemoryRootInput): Result<MemoryRoot> {
  const rootPath = normalizeMemoryRootPath(input.rootPath);
  if (!rootPath.ok) {
    return rootPath;
  }

  const defaultNamespace =
    input.defaultNamespace === undefined ? ok(DEFAULT_MEMORY_NAMESPACE) : normalizeMemoryNamespace(input.defaultNamespace);
  if (!defaultNamespace.ok) {
    return defaultNamespace;
  }

  return ok({
    rootPath: rootPath.value,
    defaultNamespace: defaultNamespace.value,
    layout: DURABLE_MEMORY_FILE_LAYOUT,
    writeApproval: DURABLE_MEMORY_WRITE_APPROVAL
  });
}

export function createMemoryWritePermissionRequest(
  namespace: MemoryNamespace,
  options: {
    durable: boolean;
    reason?: string;
    metadata?: JsonObject;
  }
): PermissionRequest {
  return {
    action: "memory.write",
    reason: options.reason ?? "Write memory record",
    resource: namespace,
    metadata: {
      ...(options.metadata ?? {}),
      namespace,
      durable: options.durable,
      requiresFilesystemWrite: options.durable
    }
  };
}

export function createMemoryReadPermissionRequest(
  namespace: MemoryNamespace,
  options: {
    reason?: string;
    metadata?: JsonObject;
  } = {}
): PermissionRequest {
  return {
    action: "memory.read",
    reason: options.reason ?? "Search memory records",
    resource: namespace,
    metadata: {
      ...(options.metadata ?? {}),
      namespace
    }
  };
}

export function createMemoryRecord(options: CreateMemoryRecordOptions): Result<MemoryRecord> {
  const input = normalizeMemoryRecordWriteInput(options.input);
  if (!input.ok) {
    return input;
  }

  const id =
    options.id === undefined ? ok(memoryRecordId(`memory-${randomUUID()}`)) : normalizeMemoryRecordId(options.id);
  if (!id.ok) {
    return id;
  }

  const timestamp = options.timestamp ?? options.clock?.nowIso() ?? new Date().toISOString();
  const record: MemoryRecord = {
    id: id.value,
    namespace: input.value.namespace,
    content: input.value.content,
    createdAt: timestamp,
    updatedAt: timestamp
  };

  if (input.value.kind !== undefined) {
    record.kind = input.value.kind;
  }

  if (input.value.metadata !== undefined) {
    record.metadata = input.value.metadata;
  }

  if (input.value.provenance !== undefined) {
    record.provenance = input.value.provenance;
  }

  return ok(record);
}

function normalizeParsedMemoryRecord(value: unknown, recordIndex: number): Result<MemoryRecord> {
  if (!isRecord(value)) {
    return memoryInvalid("Markdown memory record must be an object", {
      recordIndex
    });
  }

  const id = normalizeMemoryRecordId(value.id);
  if (!id.ok) {
    return id;
  }

  if (typeof value.createdAt !== "string" || value.createdAt.trim().length === 0 || containsNulByte(value.createdAt)) {
    return memoryInvalid("Markdown memory record createdAt must be a non-empty string", {
      field: "createdAt",
      recordIndex
    });
  }

  if (typeof value.updatedAt !== "string" || value.updatedAt.trim().length === 0 || containsNulByte(value.updatedAt)) {
    return memoryInvalid("Markdown memory record updatedAt must be a non-empty string", {
      field: "updatedAt",
      recordIndex
    });
  }

  const input = normalizeMemoryRecordWriteInput({
    namespace: value.namespace,
    content: value.content,
    kind: value.kind,
    metadata: value.metadata,
    provenance: value.provenance
  });
  if (!input.ok) {
    return input;
  }

  const record: MemoryRecord = {
    id: id.value,
    namespace: input.value.namespace,
    content: input.value.content,
    createdAt: value.createdAt,
    updatedAt: value.updatedAt
  };

  if (input.value.kind !== undefined) {
    record.kind = input.value.kind;
  }

  if (input.value.metadata !== undefined) {
    record.metadata = input.value.metadata;
  }

  if (input.value.provenance !== undefined) {
    record.provenance = input.value.provenance;
  }

  return ok(record);
}

function extractJsonFenceContent(block: string, recordIndex: number): Result<string> {
  const fenceStart = block.indexOf("```json");
  if (fenceStart < 0) {
    return memoryInvalid("Markdown memory record is missing a JSON fence", {
      recordIndex
    });
  }

  const jsonStart = block.indexOf("\n", fenceStart);
  if (jsonStart < 0) {
    return memoryInvalid("Markdown memory record JSON fence is malformed", {
      recordIndex
    });
  }

  const fenceEnd = block.indexOf("\n```", jsonStart + 1);
  if (fenceEnd < 0) {
    return memoryInvalid("Markdown memory record JSON fence is not closed", {
      recordIndex
    });
  }

  return ok(block.slice(jsonStart + 1, fenceEnd));
}

export function parseMarkdownMemoryRecords(markdown: string): Result<MemoryRecord[]> {
  const records: MemoryRecord[] = [];
  let cursor = 0;

  while (cursor < markdown.length) {
    const start = markdown.indexOf(MARKDOWN_MEMORY_RECORD_START, cursor);
    if (start < 0) {
      break;
    }

    const contentStart = start + MARKDOWN_MEMORY_RECORD_START.length;
    const end = markdown.indexOf(MARKDOWN_MEMORY_RECORD_END, contentStart);
    if (end < 0) {
      return memoryInvalid("Markdown memory record block is not closed", {
        recordIndex: records.length
      });
    }

    const jsonContent = extractJsonFenceContent(markdown.slice(contentStart, end), records.length);
    if (!jsonContent.ok) {
      return jsonContent;
    }

    let parsed: unknown;
    try {
      parsed = JSON.parse(jsonContent.value);
    } catch {
      return memoryInvalid("Markdown memory record JSON is invalid", {
        recordIndex: records.length
      });
    }

    const record = normalizeParsedMemoryRecord(parsed, records.length);
    if (!record.ok) {
      return record;
    }

    records.push(record.value);
    cursor = end + MARKDOWN_MEMORY_RECORD_END.length;
  }

  return ok(records);
}

export function formatMarkdownMemoryRecord(record: MemoryRecord): string {
  return [
    `## Memory Record: ${record.id}`,
    "",
    MARKDOWN_MEMORY_RECORD_START,
    "```json",
    JSON.stringify(record, null, 2),
    "```",
    MARKDOWN_MEMORY_RECORD_END,
    ""
  ].join("\n");
}

export class MarkdownMemoryStore implements MemoryStore {
  private readonly rootRecordRelativePath: string;

  constructor(private readonly options: MarkdownMemoryStoreOptions) {
    this.rootRecordRelativePath = options.root.layout.rootRecordFileName;
  }

  async appendDailyNote(record: DailyMemoryRecordWriteInput): Promise<MemoryRecord> {
    const normalizedDate =
      record.date === undefined ? ok(createDailyMemoryNoteDate(this.getClock())) : normalizeDailyMemoryNoteDate(record.date);
    if (!normalizedDate.ok) {
      throw normalizedDate.error;
    }

    const dailyNoteRelativePath = createDailyMemoryNoteRelativePath(this.options.root, normalizedDate.value);
    if (!dailyNoteRelativePath.ok) {
      throw dailyNoteRelativePath.error;
    }

    const memoryRecord: MemoryRecordWriteInput = {
      namespace: record.namespace,
      content: record.content,
      kind: record.kind ?? "daily-note"
    };

    if (record.metadata !== undefined) {
      memoryRecord.metadata = record.metadata;
    }

    if (record.provenance !== undefined) {
      memoryRecord.provenance = record.provenance;
    }

    const input = normalizeMemoryRecordWriteInput(memoryRecord);
    if (!input.ok) {
      throw input.error;
    }

    let decision: PermissionDecision;

    try {
      decision = await decidePermissionWithAudit(
        this.options.policy,
        createMemoryWritePermissionRequest(input.value.namespace, {
          durable: true,
          metadata: {
            operation: "append",
            fileName: dailyNoteRelativePath.value,
            dailyNoteDate: normalizedDate.value
          }
        }),
        this.options.auditContext
      );
    } catch (error) {
      await appendAuditEvent(this.options.auditContext, {
        sourcePackage: "@dominic-nexus/memory",
        action: "memory.write",
        decision: "not_applicable",
        resource: {
          type: "memory",
          id: input.value.namespace,
          name: input.value.namespace
        },
        outcome: "failed",
        metadata: {
          namespace: input.value.namespace,
          durable: true,
          fileName: dailyNoteRelativePath.value,
          dailyNoteDate: normalizedDate.value,
          errorName: safeErrorName(error)
        }
      });

      throw toAppError(error, {
        code: "unexpected",
        message: "Daily memory note write permission check failed",
        context: {
          namespace: input.value.namespace
        }
      });
    }

    if (!decision.allowed) {
      await appendAuditEvent(this.options.auditContext, {
        sourcePackage: "@dominic-nexus/memory",
        action: "memory.write",
        decision: "denied",
        resource: {
          type: "memory",
          id: input.value.namespace,
          name: input.value.namespace
        },
        outcome: "denied",
        metadata: {
          namespace: input.value.namespace,
          durable: true,
          fileName: dailyNoteRelativePath.value,
          dailyNoteDate: normalizedDate.value,
          decisionReason: decision.reason
        }
      });

      throw new AppError({
        code: "memory.write_denied",
        message: "Daily memory note write denied",
        context: {
          namespace: input.value.namespace
        }
      });
    }

    const recordOptions: CreateMemoryRecordOptions = {
      input: input.value
    };
    const recordId = this.options.createRecordId?.();
    const clock = this.getClock();

    if (recordId !== undefined) {
      recordOptions.id = recordId;
    }

    if (clock !== undefined) {
      recordOptions.clock = clock;
    }

    const stored = createMemoryRecord(recordOptions);
    if (!stored.ok) {
      throw stored.error;
    }

    const authorization = await this.authorizeDailyNoteFile("append", input.value.namespace, normalizedDate.value, {
      recordId: stored.value.id
    });
    if (!authorization.ok) {
      await appendAuditEvent(this.options.auditContext, {
        sourcePackage: "@dominic-nexus/memory",
        action: "memory.write",
        decision: isAuthorizationDenied(authorization.error) ? "denied" : "not_applicable",
        resource: {
          type: "memory",
          id: input.value.namespace,
          name: input.value.namespace
        },
        outcome: isAuthorizationDenied(authorization.error) ? "denied" : "failed",
        metadata: {
          namespace: input.value.namespace,
          recordId: stored.value.id,
          durable: true,
          fileName: dailyNoteRelativePath.value,
          dailyNoteDate: normalizedDate.value,
          operation: "append",
          errorCode: authorization.error.code
        }
      });

      throw authorization.error;
    }

    try {
      await this.options.fileAccess.appendText(authorization.value.normalizedPath, formatMarkdownMemoryRecord(stored.value));
    } catch (error) {
      await appendAuditEvent(this.options.auditContext, {
        sourcePackage: "@dominic-nexus/memory",
        action: "memory.write",
        decision: "allowed",
        resource: {
          type: "memory",
          id: stored.value.namespace,
          name: stored.value.namespace
        },
        outcome: "failed",
        metadata: {
          namespace: stored.value.namespace,
          recordId: stored.value.id,
          durable: true,
          fileName: dailyNoteRelativePath.value,
          dailyNoteDate: normalizedDate.value,
          operation: "append",
          errorName: safeErrorName(error)
        }
      });

      throw toAppError(error, {
        code: "unexpected",
        message: "Daily memory note append failed",
        context: {
          namespace: stored.value.namespace,
          fileName: dailyNoteRelativePath.value
        }
      });
    }

    await appendAuditEvent(this.options.auditContext, {
      sourcePackage: "@dominic-nexus/memory",
      action: "memory.write",
      decision: "allowed",
      resource: {
        type: "memory",
        id: stored.value.namespace,
        name: stored.value.namespace
      },
      outcome: "succeeded",
      metadata: {
        namespace: stored.value.namespace,
        recordId: stored.value.id,
        durable: true,
        fileName: dailyNoteRelativePath.value,
        dailyNoteDate: normalizedDate.value,
        operation: "append"
      }
    });

    return stored.value;
  }

  async readDailyNote(
    date: string | DailyMemoryNoteDate,
    namespace: string | MemoryNamespace,
    options: DailyMemoryNoteReadOptions = {}
  ): Promise<MemoryRecord[]> {
    const searchOptions: DailyMemoryNoteSearchOptions = {
      namespace,
      startDate: date,
      endDate: date
    };

    if (options.limit !== undefined) {
      searchOptions.limit = options.limit;
    }

    return this.searchDailyNotes(searchOptions);
  }

  async searchDailyNotes(options: DailyMemoryNoteSearchOptions): Promise<MemoryRecord[]> {
    const normalizedNamespace = normalizeMemoryNamespace(options.namespace);
    if (!normalizedNamespace.ok) {
      throw normalizedNamespace.error;
    }

    const dates = createDailyMemoryNoteDateRange(options.startDate, options.endDate);
    if (!dates.ok) {
      throw dates.error;
    }

    const limit = normalizeDailyMemoryNoteLimit(options.limit);
    if (!limit.ok) {
      throw limit.error;
    }

    const startSearchDate = dates.value[0] as DailyMemoryNoteDate;
    const endSearchDate = dates.value[dates.value.length - 1] as DailyMemoryNoteDate;
    let decision: PermissionDecision;

    try {
      decision = await decidePermissionWithAudit(
        this.options.policy,
        createMemoryReadPermissionRequest(normalizedNamespace.value, {
          reason: "Search daily memory notes",
          metadata: {
            operation: "daily-note-search",
            startDate: startSearchDate,
            endDate: endSearchDate,
            limit: limit.value
          }
        }),
        this.options.auditContext
      );
    } catch (error) {
      await appendAuditEvent(this.options.auditContext, {
        sourcePackage: "@dominic-nexus/memory",
        action: "memory.read",
        decision: "not_applicable",
        resource: {
          type: "memory",
          id: normalizedNamespace.value,
          name: normalizedNamespace.value
        },
        outcome: "failed",
        metadata: {
          namespace: normalizedNamespace.value,
          operation: "daily-note-search",
          errorName: safeErrorName(error)
        }
      });

      throw toAppError(error, {
        code: "unexpected",
        message: "Daily memory note read permission check failed",
        context: {
          namespace: normalizedNamespace.value
        }
      });
    }

    if (!decision.allowed) {
      await appendAuditEvent(this.options.auditContext, {
        sourcePackage: "@dominic-nexus/memory",
        action: "memory.read",
        decision: "denied",
        resource: {
          type: "memory",
          id: normalizedNamespace.value,
          name: normalizedNamespace.value
        },
        outcome: "denied",
        metadata: {
          namespace: normalizedNamespace.value,
          operation: "daily-note-search",
          decisionReason: decision.reason
        }
      });

      throw new AppError({
        code: "memory.read_denied",
        message: "Daily memory note read denied",
        context: {
          namespace: normalizedNamespace.value
        }
      });
    }

    const results: MemoryRecord[] = [];
    let scannedFileCount = 0;
    let missingFileCount = 0;
    let truncated = false;

    for (const date of dates.value) {
      const dailyNoteRelativePath = createDailyMemoryNoteRelativePath(this.options.root, date);
      if (!dailyNoteRelativePath.ok) {
        throw dailyNoteRelativePath.error;
      }

      const authorization = await this.authorizeDailyNoteFile("read", normalizedNamespace.value, date);
      if (!authorization.ok) {
        await appendAuditEvent(this.options.auditContext, {
          sourcePackage: "@dominic-nexus/memory",
          action: "memory.read",
          decision: isAuthorizationDenied(authorization.error) ? "denied" : "not_applicable",
          resource: {
            type: "memory",
            id: normalizedNamespace.value,
            name: normalizedNamespace.value
          },
          outcome: isAuthorizationDenied(authorization.error) ? "denied" : "failed",
          metadata: {
            namespace: normalizedNamespace.value,
            fileName: dailyNoteRelativePath.value,
            dailyNoteDate: date,
            operation: "read",
            errorCode: authorization.error.code
          }
        });

        throw authorization.error;
      }

      let markdown: string | undefined;
      try {
        markdown = await this.options.fileAccess.readText(authorization.value.normalizedPath);
      } catch (error) {
        await appendAuditEvent(this.options.auditContext, {
          sourcePackage: "@dominic-nexus/memory",
          action: "memory.read",
          decision: "allowed",
          resource: {
            type: "memory",
            id: normalizedNamespace.value,
            name: normalizedNamespace.value
          },
          outcome: "failed",
          metadata: {
            namespace: normalizedNamespace.value,
            fileName: dailyNoteRelativePath.value,
            dailyNoteDate: date,
            operation: "read",
            errorName: safeErrorName(error)
          }
        });

        throw toAppError(error, {
          code: "unexpected",
          message: "Daily memory note read failed",
          context: {
            namespace: normalizedNamespace.value,
            fileName: dailyNoteRelativePath.value
          }
        });
      }

      scannedFileCount += 1;
      if (markdown === undefined) {
        missingFileCount += 1;
        continue;
      }

      const parsed = parseMarkdownMemoryRecords(markdown);
      if (!parsed.ok) {
        await appendAuditEvent(this.options.auditContext, {
          sourcePackage: "@dominic-nexus/memory",
          action: "memory.read",
          decision: "allowed",
          resource: {
            type: "memory",
            id: normalizedNamespace.value,
            name: normalizedNamespace.value
          },
          outcome: "failed",
          metadata: {
            namespace: normalizedNamespace.value,
            fileName: dailyNoteRelativePath.value,
            dailyNoteDate: date,
            operation: "read",
            errorCode: parsed.error.code
          }
        });

        throw parsed.error;
      }

      for (const memoryRecord of parsed.value) {
        if (memoryRecord.namespace !== normalizedNamespace.value) {
          continue;
        }

        results.push(memoryRecord);
        if (results.length >= limit.value) {
          truncated = true;
          break;
        }
      }

      if (truncated) {
        break;
      }
    }

    await appendAuditEvent(this.options.auditContext, {
      sourcePackage: "@dominic-nexus/memory",
      action: "memory.read",
      decision: "allowed",
      resource: {
        type: "memory",
        id: normalizedNamespace.value,
        name: normalizedNamespace.value
      },
      outcome: "succeeded",
      metadata: {
        namespace: normalizedNamespace.value,
        resultCount: results.length,
        durable: true,
        operation: "daily-note-search",
        startDate: startSearchDate,
        endDate: endSearchDate,
        limit: limit.value,
        scannedFileCount,
        missingFileCount,
        truncated
      }
    });

    return results;
  }

  async write(record: MemoryRecordWriteInput): Promise<MemoryRecord> {
    const input = normalizeMemoryRecordWriteInput(record);
    if (!input.ok) {
      throw input.error;
    }

    let decision: PermissionDecision;

    try {
      decision = await decidePermissionWithAudit(
        this.options.policy,
        createMemoryWritePermissionRequest(input.value.namespace, {
          durable: true,
          metadata: {
            operation: "append",
            fileName: this.rootRecordRelativePath
          }
        }),
        this.options.auditContext
      );
    } catch (error) {
      await appendAuditEvent(this.options.auditContext, {
        sourcePackage: "@dominic-nexus/memory",
        action: "memory.write",
        decision: "not_applicable",
        resource: {
          type: "memory",
          id: input.value.namespace,
          name: input.value.namespace
        },
        outcome: "failed",
        metadata: {
          namespace: input.value.namespace,
          durable: true,
          fileName: this.rootRecordRelativePath,
          errorName: safeErrorName(error)
        }
      });

      throw toAppError(error, {
        code: "unexpected",
        message: "Markdown memory write permission check failed",
        context: {
          namespace: input.value.namespace
        }
      });
    }

    if (!decision.allowed) {
      await appendAuditEvent(this.options.auditContext, {
        sourcePackage: "@dominic-nexus/memory",
        action: "memory.write",
        decision: "denied",
        resource: {
          type: "memory",
          id: input.value.namespace,
          name: input.value.namespace
        },
        outcome: "denied",
        metadata: {
          namespace: input.value.namespace,
          durable: true,
          fileName: this.rootRecordRelativePath,
          decisionReason: decision.reason
        }
      });

      throw new AppError({
        code: "memory.write_denied",
        message: "Markdown memory write denied",
        context: {
          namespace: input.value.namespace
        }
      });
    }

    const recordOptions: CreateMemoryRecordOptions = {
      input: input.value
    };
    const recordId = this.options.createRecordId?.();
    const clock = this.options.clock ?? this.options.auditContext?.clock;

    if (recordId !== undefined) {
      recordOptions.id = recordId;
    }

    if (clock !== undefined) {
      recordOptions.clock = clock;
    }

    const stored = createMemoryRecord(recordOptions);
    if (!stored.ok) {
      throw stored.error;
    }

    const authorization = await this.authorizeRootRecordFile("append", input.value.namespace, {
      recordId: stored.value.id
    });
    if (!authorization.ok) {
      await appendAuditEvent(this.options.auditContext, {
        sourcePackage: "@dominic-nexus/memory",
        action: "memory.write",
        decision: isAuthorizationDenied(authorization.error) ? "denied" : "not_applicable",
        resource: {
          type: "memory",
          id: input.value.namespace,
          name: input.value.namespace
        },
        outcome: isAuthorizationDenied(authorization.error) ? "denied" : "failed",
        metadata: {
          namespace: input.value.namespace,
          recordId: stored.value.id,
          durable: true,
          fileName: this.rootRecordRelativePath,
          operation: "append",
          errorCode: authorization.error.code
        }
      });

      throw authorization.error;
    }

    try {
      await this.options.fileAccess.appendText(authorization.value.normalizedPath, formatMarkdownMemoryRecord(stored.value));
    } catch (error) {
      await appendAuditEvent(this.options.auditContext, {
        sourcePackage: "@dominic-nexus/memory",
        action: "memory.write",
        decision: "allowed",
        resource: {
          type: "memory",
          id: stored.value.namespace,
          name: stored.value.namespace
        },
        outcome: "failed",
        metadata: {
          namespace: stored.value.namespace,
          recordId: stored.value.id,
          durable: true,
          fileName: this.rootRecordRelativePath,
          operation: "append",
          errorName: safeErrorName(error)
        }
      });

      throw toAppError(error, {
        code: "unexpected",
        message: "Markdown memory append failed",
        context: {
          namespace: stored.value.namespace,
          fileName: this.rootRecordRelativePath
        }
      });
    }

    await appendAuditEvent(this.options.auditContext, {
      sourcePackage: "@dominic-nexus/memory",
      action: "memory.write",
      decision: "allowed",
      resource: {
        type: "memory",
        id: stored.value.namespace,
        name: stored.value.namespace
      },
      outcome: "succeeded",
      metadata: {
        namespace: stored.value.namespace,
        recordId: stored.value.id,
        durable: true,
        fileName: this.rootRecordRelativePath,
        operation: "append"
      }
    });

    return stored.value;
  }

  async search(namespace: string | MemoryNamespace): Promise<MemoryRecord[]> {
    const normalizedNamespace = normalizeMemoryNamespace(namespace);
    if (!normalizedNamespace.ok) {
      throw normalizedNamespace.error;
    }

    let decision: PermissionDecision;

    try {
      decision = await decidePermissionWithAudit(
        this.options.policy,
        createMemoryReadPermissionRequest(normalizedNamespace.value, {
          metadata: {
            fileName: this.rootRecordRelativePath
          }
        }),
        this.options.auditContext
      );
    } catch (error) {
      await appendAuditEvent(this.options.auditContext, {
        sourcePackage: "@dominic-nexus/memory",
        action: "memory.read",
        decision: "not_applicable",
        resource: {
          type: "memory",
          id: normalizedNamespace.value,
          name: normalizedNamespace.value
        },
        outcome: "failed",
        metadata: {
          namespace: normalizedNamespace.value,
          fileName: this.rootRecordRelativePath,
          errorName: safeErrorName(error)
        }
      });

      throw toAppError(error, {
        code: "unexpected",
        message: "Markdown memory read permission check failed",
        context: {
          namespace: normalizedNamespace.value
        }
      });
    }

    if (!decision.allowed) {
      await appendAuditEvent(this.options.auditContext, {
        sourcePackage: "@dominic-nexus/memory",
        action: "memory.read",
        decision: "denied",
        resource: {
          type: "memory",
          id: normalizedNamespace.value,
          name: normalizedNamespace.value
        },
        outcome: "denied",
        metadata: {
          namespace: normalizedNamespace.value,
          fileName: this.rootRecordRelativePath,
          decisionReason: decision.reason
        }
      });

      throw new AppError({
        code: "memory.read_denied",
        message: "Markdown memory read denied",
        context: {
          namespace: normalizedNamespace.value
        }
      });
    }

    const authorization = await this.authorizeRootRecordFile("read", normalizedNamespace.value);
    if (!authorization.ok) {
      await appendAuditEvent(this.options.auditContext, {
        sourcePackage: "@dominic-nexus/memory",
        action: "memory.read",
        decision: isAuthorizationDenied(authorization.error) ? "denied" : "not_applicable",
        resource: {
          type: "memory",
          id: normalizedNamespace.value,
          name: normalizedNamespace.value
        },
        outcome: isAuthorizationDenied(authorization.error) ? "denied" : "failed",
        metadata: {
          namespace: normalizedNamespace.value,
          fileName: this.rootRecordRelativePath,
          operation: "read",
          errorCode: authorization.error.code
        }
      });

      throw authorization.error;
    }

    let markdown: string | undefined;
    try {
      markdown = await this.options.fileAccess.readText(authorization.value.normalizedPath);
    } catch (error) {
      await appendAuditEvent(this.options.auditContext, {
        sourcePackage: "@dominic-nexus/memory",
        action: "memory.read",
        decision: "allowed",
        resource: {
          type: "memory",
          id: normalizedNamespace.value,
          name: normalizedNamespace.value
        },
        outcome: "failed",
        metadata: {
          namespace: normalizedNamespace.value,
          fileName: this.rootRecordRelativePath,
          operation: "read",
          errorName: safeErrorName(error)
        }
      });

      throw toAppError(error, {
        code: "unexpected",
        message: "Markdown memory read failed",
        context: {
          namespace: normalizedNamespace.value,
          fileName: this.rootRecordRelativePath
        }
      });
    }

    if (markdown === undefined) {
      await this.auditReadSuccess(normalizedNamespace.value, 0, true);
      return [];
    }

    const parsed = parseMarkdownMemoryRecords(markdown);
    if (!parsed.ok) {
      await appendAuditEvent(this.options.auditContext, {
        sourcePackage: "@dominic-nexus/memory",
        action: "memory.read",
        decision: "allowed",
        resource: {
          type: "memory",
          id: normalizedNamespace.value,
          name: normalizedNamespace.value
        },
        outcome: "failed",
        metadata: {
          namespace: normalizedNamespace.value,
          fileName: this.rootRecordRelativePath,
          operation: "read",
          errorCode: parsed.error.code
        }
      });

      throw parsed.error;
    }

    const results = parsed.value.filter((memoryRecord) => memoryRecord.namespace === normalizedNamespace.value);
    await this.auditReadSuccess(normalizedNamespace.value, results.length, false);
    return results;
  }

  private async authorizeRootRecordFile(
    operation: MemoryFileOperation,
    namespace: MemoryNamespace,
    metadata: JsonObject = {}
  ): Promise<Result<MemoryFileAuthorization>> {
    try {
      return await this.options.authorizer({
        root: this.options.root,
        operation,
        relativePath: this.rootRecordRelativePath,
        reason: operation === "read" ? "Read root Markdown memory file" : "Write root Markdown memory file",
        metadata: {
          ...metadata,
          namespace,
          durable: true,
          fileName: this.rootRecordRelativePath,
          operation
        }
      });
    } catch (error) {
      return err(
        toAppError(error, {
          code: "unexpected",
          message: "Markdown memory file authorization failed",
          context: {
            namespace,
            fileName: this.rootRecordRelativePath,
            operation
          }
        })
      );
    }
  }

  private async authorizeDailyNoteFile(
    operation: MemoryFileOperation,
    namespace: MemoryNamespace,
    date: DailyMemoryNoteDate,
    metadata: JsonObject = {}
  ): Promise<Result<MemoryFileAuthorization>> {
    const dailyNoteRelativePath = createDailyMemoryNoteRelativePath(this.options.root, date);
    if (!dailyNoteRelativePath.ok) {
      return err(dailyNoteRelativePath.error);
    }

    try {
      return await this.options.authorizer({
        root: this.options.root,
        operation,
        relativePath: dailyNoteRelativePath.value,
        reason: operation === "read" ? "Read daily Markdown memory note" : "Write daily Markdown memory note",
        metadata: {
          ...metadata,
          namespace,
          durable: true,
          fileName: dailyNoteRelativePath.value,
          dailyNoteDate: date,
          operation
        }
      });
    } catch (error) {
      return err(
        toAppError(error, {
          code: "unexpected",
          message: "Daily memory note file authorization failed",
          context: {
            namespace,
            fileName: dailyNoteRelativePath.value,
            dailyNoteDate: date,
            operation
          }
        })
      );
    }
  }

  private getClock(): Clock | undefined {
    return this.options.clock ?? this.options.auditContext?.clock;
  }

  private async auditReadSuccess(namespace: MemoryNamespace, resultCount: number, missingFile: boolean): Promise<void> {
    await appendAuditEvent(this.options.auditContext, {
      sourcePackage: "@dominic-nexus/memory",
      action: "memory.read",
      decision: "allowed",
      resource: {
        type: "memory",
        id: namespace,
        name: namespace
      },
      outcome: "succeeded",
      metadata: {
        namespace,
        resultCount,
        durable: true,
        fileName: this.rootRecordRelativePath,
        missingFile
      }
    });
  }
}

export class InMemoryStore implements MemoryStore {
  private readonly records = new Map<MemoryRecordId, MemoryRecord>();

  constructor(
    private readonly policy: PolicyEngine,
    private readonly auditContext?: OptionalAuditRuntimeContext,
    private readonly options: InMemoryStoreOptions = {}
  ) {}

  async write(record: MemoryRecordWriteInput): Promise<MemoryRecord> {
    const input = normalizeMemoryRecordWriteInput(record);
    if (!input.ok) {
      throw input.error;
    }

    let decision: PermissionDecision;

    try {
      decision = await decidePermissionWithAudit(
        this.policy,
        createMemoryWritePermissionRequest(input.value.namespace, {
          durable: false
        }),
        this.auditContext
      );
    } catch (error) {
      await appendAuditEvent(this.auditContext, {
        sourcePackage: "@dominic-nexus/memory",
        action: "memory.write",
        decision: "not_applicable",
        resource: {
          type: "memory",
          id: input.value.namespace,
          name: input.value.namespace
        },
        outcome: "failed",
        metadata: {
          namespace: input.value.namespace,
          errorName: safeErrorName(error)
        }
      });

      throw toAppError(error, {
        code: "unexpected",
        message: "Memory write permission check failed",
        context: {
          namespace: input.value.namespace
        }
      });
    }

    if (!decision.allowed) {
      await appendAuditEvent(this.auditContext, {
        sourcePackage: "@dominic-nexus/memory",
        action: "memory.write",
        decision: "denied",
        resource: {
          type: "memory",
          id: input.value.namespace,
          name: input.value.namespace
        },
        outcome: "denied",
        metadata: {
          namespace: input.value.namespace,
          decisionReason: decision.reason
        }
      });

      throw new AppError({
        code: "memory.write_denied",
        message: "Memory write denied",
        context: {
          namespace: input.value.namespace
        }
      });
    }

    const recordOptions: CreateMemoryRecordOptions = {
      input: input.value
    };
    const recordId = this.options.createRecordId?.();
    const clock = this.options.clock ?? this.auditContext?.clock;

    if (recordId !== undefined) {
      recordOptions.id = recordId;
    }

    if (clock !== undefined) {
      recordOptions.clock = clock;
    }

    const stored = createMemoryRecord(recordOptions);
    if (!stored.ok) {
      throw stored.error;
    }

    this.records.set(stored.value.id, stored.value);
    await appendAuditEvent(this.auditContext, {
      sourcePackage: "@dominic-nexus/memory",
      action: "memory.write",
      decision: "allowed",
      resource: {
        type: "memory",
        id: stored.value.namespace,
        name: stored.value.namespace
      },
      outcome: "succeeded",
      metadata: {
        namespace: stored.value.namespace,
        recordId: stored.value.id,
        durable: false
      }
    });

    return stored.value;
  }

  async search(namespace: string | MemoryNamespace): Promise<MemoryRecord[]> {
    const normalizedNamespace = normalizeMemoryNamespace(namespace);
    if (!normalizedNamespace.ok) {
      throw normalizedNamespace.error;
    }

    let decision: PermissionDecision;

    try {
      decision = await decidePermissionWithAudit(
        this.policy,
        createMemoryReadPermissionRequest(normalizedNamespace.value),
        this.auditContext
      );
    } catch (error) {
      await appendAuditEvent(this.auditContext, {
        sourcePackage: "@dominic-nexus/memory",
        action: "memory.read",
        decision: "not_applicable",
        resource: {
          type: "memory",
          id: normalizedNamespace.value,
          name: normalizedNamespace.value
        },
        outcome: "failed",
        metadata: {
          namespace: normalizedNamespace.value,
          errorName: safeErrorName(error)
        }
      });

      throw toAppError(error, {
        code: "unexpected",
        message: "Memory read permission check failed",
        context: {
          namespace: normalizedNamespace.value
        }
      });
    }

    if (!decision.allowed) {
      await appendAuditEvent(this.auditContext, {
        sourcePackage: "@dominic-nexus/memory",
        action: "memory.read",
        decision: "denied",
        resource: {
          type: "memory",
          id: normalizedNamespace.value,
          name: normalizedNamespace.value
        },
        outcome: "denied",
        metadata: {
          namespace: normalizedNamespace.value,
          decisionReason: decision.reason
        }
      });

      throw new AppError({
        code: "memory.read_denied",
        message: "Memory read denied",
        context: {
          namespace: normalizedNamespace.value
        }
      });
    }

    const results = [...this.records.values()].filter((record) => record.namespace === normalizedNamespace.value);

    await appendAuditEvent(this.auditContext, {
      sourcePackage: "@dominic-nexus/memory",
      action: "memory.read",
      decision: "allowed",
      resource: {
        type: "memory",
        id: normalizedNamespace.value,
        name: normalizedNamespace.value
      },
      outcome: "succeeded",
      metadata: {
        namespace: normalizedNamespace.value,
        resultCount: results.length
      }
    });

    return results;
  }
}
