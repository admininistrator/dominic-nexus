import { spawn } from "node:child_process";
import { realpathSync } from "node:fs";
import { open, rename, rm, stat, writeFile } from "node:fs/promises";
import path from "node:path";
import { appendAuditEvent, type OptionalAuditRuntimeContext } from "@dominic-nexus/audit";
import {
  decidePermissionWithAudit,
  NetworkPolicy,
  ShellPolicy,
  validateShellExecutionRequest,
  type NormalizedShellExecutionRequest,
  type PermissionAction,
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
  toolName,
  type JsonObject,
  type JsonValue,
  type Result,
  type ToolName
} from "@dominic-nexus/shared";

export type FilesystemPathPlatform = "posix" | "win32";

export type FilesystemOperation = "read" | "write";

export interface FilesystemAccess {
  realpath(path: string): Promise<string> | string;
}

export interface FilesystemRootPolicyOptions {
  roots: string[];
  cwd?: string;
  platform?: FilesystemPathPlatform;
  access?: FilesystemAccess;
}

export interface FilesystemPathResolution {
  operation: FilesystemOperation;
  requestedPath: string;
  normalizedPath: string;
  matchedRoot: string;
  realPath?: string;
}

export interface FilesystemAuthorization extends FilesystemPathResolution {
  permission: PermissionAction;
}

export interface FilesystemAuthorizationRequest {
  path: string;
  policy: PolicyEngine;
  audit?: OptionalAuditRuntimeContext;
  reason?: string;
  metadata?: Record<string, JsonValue>;
}

interface NormalizedFilesystemRoot {
  normalizedPath: string;
  comparisonPath: string;
}

type PathApi = typeof path.posix | typeof path.win32;

const DEFAULT_FILESYSTEM_ACCESS: FilesystemAccess = {
  realpath(filePath) {
    return realpathSync.native(filePath);
  }
};

const WINDOWS_DRIVE_RELATIVE_PATH_PATTERN = /^[a-zA-Z]:(?![\\/])/;
const WINDOWS_PATH_PATTERN = /^(?:[a-zA-Z]:[\\/]|[a-zA-Z]:(?![\\/])|\\\\|.*\\)/;

function inferFilesystemPlatform(roots: string[]): FilesystemPathPlatform {
  if (roots.some((root) => WINDOWS_PATH_PATTERN.test(root))) {
    return "win32";
  }

  return process.platform === "win32" ? "win32" : "posix";
}

function getPathApi(platform: FilesystemPathPlatform): PathApi {
  return platform === "win32" ? path.win32 : path.posix;
}

function getPathApiForResolvedPath(filePath: string): PathApi {
  return WINDOWS_PATH_PATTERN.test(filePath) ? path.win32 : path.posix;
}

function filesystemPathError(message: string, context: Record<string, JsonValue>): Result<never> {
  return err(
    new AppError({
      code: "filesystem.root_violation",
      message,
      context
    })
  );
}

function validateFilesystemPathString(
  filePath: string,
  label: string,
  platform: FilesystemPathPlatform
): Result<string> {
  if (filePath.trim().length === 0) {
    return filesystemPathError("Filesystem path must be a non-empty string", {
      field: label
    });
  }

  if (filePath.includes("\0")) {
    return filesystemPathError("Filesystem path must not contain NUL bytes", {
      field: label
    });
  }

  if (platform === "win32" && WINDOWS_DRIVE_RELATIVE_PATH_PATTERN.test(filePath)) {
    return filesystemPathError("Windows drive-relative paths are not allowed", {
      field: label
    });
  }

  return ok(filePath);
}

function stripTrailingSeparators(filePath: string, pathApi: PathApi): string {
  const root = pathApi.parse(filePath).root;
  let stripped = filePath;

  while (stripped.length > root.length && (stripped.endsWith("/") || stripped.endsWith("\\"))) {
    stripped = stripped.slice(0, -1);
  }

  return stripped;
}

function normalizeForComparison(filePath: string, platform: FilesystemPathPlatform, pathApi: PathApi): string {
  const normalized = stripTrailingSeparators(pathApi.normalize(filePath), pathApi);
  return platform === "win32" ? normalized.toLowerCase() : normalized;
}

function isSameOrChildPath(candidate: string, root: string, pathApi: PathApi): boolean {
  if (candidate === root) {
    return true;
  }

  const rootWithSeparator = root.endsWith(pathApi.sep) ? root : `${root}${pathApi.sep}`;
  return candidate.startsWith(rootWithSeparator);
}

export class FilesystemRootPolicy {
  readonly roots: readonly string[];
  private readonly access: FilesystemAccess;
  private readonly cwd: string;
  private readonly normalizedRoots: NormalizedFilesystemRoot[];
  private readonly pathApi: PathApi;
  private readonly platform: FilesystemPathPlatform;

  constructor(options: FilesystemRootPolicyOptions) {
    this.platform = options.platform ?? inferFilesystemPlatform(options.roots);
    this.pathApi = getPathApi(this.platform);
    this.access = options.access ?? DEFAULT_FILESYSTEM_ACCESS;

    if (options.roots.length === 0) {
      throw new AppError({
        code: "filesystem.root_violation",
        message: "At least one filesystem root is required"
      });
    }

    this.cwd = this.normalizeAbsolutePath(options.cwd ?? process.cwd(), "cwd");
    this.normalizedRoots = options.roots.map((root) => {
      const rootPath = this.pathApi.isAbsolute(root) ? root : this.pathApi.resolve(this.cwd, root);
      const normalizedPath = this.normalizeAbsolutePath(rootPath, "root");
      return {
        normalizedPath,
        comparisonPath: normalizeForComparison(normalizedPath, this.platform, this.pathApi)
      };
    });
    this.roots = this.normalizedRoots.map((root) => root.normalizedPath);
  }

  async resolvePath(filePath: string, operation: FilesystemOperation): Promise<Result<FilesystemPathResolution>> {
    const requestedPath = filePath;
    const normalizedPathResult = this.normalizeRequestedPath(filePath);
    if (!normalizedPathResult.ok) {
      return normalizedPathResult;
    }

    const normalizedPath = normalizedPathResult.value;
    const matchedRoot = this.findMatchingRoot(normalizedPath);
    if (matchedRoot === undefined) {
      return filesystemPathError("Filesystem path is outside approved roots", {
        operation,
        requestedPath,
        normalizedPath
      });
    }

    const realPath = await this.tryRealpath(normalizedPath);
    if (realPath !== undefined) {
      const realMatchedRoot = this.findMatchingRoot(realPath);
      if (realMatchedRoot === undefined) {
        return filesystemPathError("Filesystem real path is outside approved roots", {
          operation,
          requestedPath,
          normalizedPath,
          realPath
        });
      }

      return ok({
        operation,
        requestedPath,
        normalizedPath,
        matchedRoot: realMatchedRoot.normalizedPath,
        realPath
      });
    }

    return ok({
      operation,
      requestedPath,
      normalizedPath,
      matchedRoot: matchedRoot.normalizedPath
    });
  }

  private normalizeRequestedPath(filePath: string): Result<string> {
    const validated = validateFilesystemPathString(filePath, "path", this.platform);
    if (!validated.ok) {
      return validated;
    }

    const pathToNormalize = this.pathApi.isAbsolute(filePath) ? filePath : this.pathApi.resolve(this.cwd, filePath);
    return ok(this.normalizeAbsolutePath(pathToNormalize, "path"));
  }

  private normalizeAbsolutePath(filePath: string, label: string): string {
    const validated = validateFilesystemPathString(filePath, label, this.platform);
    if (!validated.ok) {
      throw validated.error;
    }

    const resolvedPath = this.pathApi.resolve(filePath);
    const normalizedPath = stripTrailingSeparators(this.pathApi.normalize(resolvedPath), this.pathApi);

    if (!this.pathApi.isAbsolute(normalizedPath)) {
      throw new AppError({
        code: "filesystem.root_violation",
        message: "Filesystem path must resolve to an absolute path",
        context: {
          field: label
        }
      });
    }

    return normalizedPath;
  }

  private findMatchingRoot(filePath: string): NormalizedFilesystemRoot | undefined {
    const comparisonPath = normalizeForComparison(filePath, this.platform, this.pathApi);
    return this.normalizedRoots.find((root) => isSameOrChildPath(comparisonPath, root.comparisonPath, this.pathApi));
  }

  private async tryRealpath(filePath: string): Promise<string | undefined> {
    try {
      const realPath = await this.access.realpath(filePath);
      return this.normalizeAbsolutePath(realPath, "realPath");
    } catch {
      return undefined;
    }
  }
}

async function authorizeFilesystemOperation(
  filesystem: FilesystemRootPolicy,
  request: FilesystemAuthorizationRequest,
  operation: FilesystemOperation,
  permission: PermissionAction
): Promise<Result<FilesystemAuthorization>> {
  const resolvedPath = await filesystem.resolvePath(request.path, operation);
  if (!resolvedPath.ok) {
    return resolvedPath;
  }

  let decision: PermissionDecision;

  try {
    decision = await decidePermissionWithAudit(
      request.policy,
      {
        action: permission,
        reason: request.reason ?? `Authorize filesystem ${operation}`,
        resource: resolvedPath.value.normalizedPath,
        metadata: {
          ...(request.metadata ?? {}),
          operation,
          requestedPath: resolvedPath.value.requestedPath,
          normalizedPath: resolvedPath.value.normalizedPath
        }
      },
      request.audit
    );
  } catch (error) {
    return err(
      toAppError(error, {
        code: "filesystem.permission_denied",
        message: `Filesystem ${operation} permission check failed`,
        context: {
          action: permission,
          operation
        }
      })
    );
  }

  if (!decision.allowed) {
    return err(
      new AppError({
        code: "filesystem.permission_denied",
        message: `Filesystem ${operation} permission denied`,
        context: {
          action: permission,
          operation,
          path: resolvedPath.value.normalizedPath
        }
      })
    );
  }

  return ok({
    ...resolvedPath.value,
    permission
  });
}

export async function authorizeFilesystemRead(
  filesystem: FilesystemRootPolicy,
  request: FilesystemAuthorizationRequest
): Promise<Result<FilesystemAuthorization>> {
  return authorizeFilesystemOperation(filesystem, request, "read", "filesystem.read");
}

export async function authorizeFilesystemWrite(
  filesystem: FilesystemRootPolicy,
  request: FilesystemAuthorizationRequest
): Promise<Result<FilesystemAuthorization>> {
  return authorizeFilesystemOperation(filesystem, request, "write", "filesystem.write");
}

export interface ToolExecutionContext {
  policy: PolicyEngine;
  audit?: OptionalAuditRuntimeContext;
  metadata?: Record<string, JsonValue>;
  signal?: AbortSignal;
}

export interface ReadFileToolOptions {
  filesystem: FilesystemRootPolicy;
  access?: ReadFileToolAccess;
  defaultMaxBytes?: number;
  absoluteMaxBytes?: number;
}

export interface ReadFileToolAccess {
  readBytes(path: string, byteLimit: number): Promise<Uint8Array> | Uint8Array;
}

export interface WriteFileToolOptions {
  filesystem: FilesystemRootPolicy;
  access?: WriteFileToolAccess;
  absoluteMaxBytes?: number;
}

export interface WriteFileToolAccess {
  directoryExists(path: string): Promise<boolean> | boolean;
  fileExists(path: string): Promise<boolean> | boolean;
  createFile(path: string, content: string, encoding: "utf8"): Promise<void> | void;
  overwriteFile(path: string, content: string, encoding: "utf8", temporaryPath: string): Promise<void> | void;
}

export type WebFetchRedirectPolicy = "error" | "follow";

export interface WebFetchToolOptions {
  transport?: WebFetchTransport;
  defaultMaxBytes?: number;
  absoluteMaxBytes?: number;
}

export interface WebFetchTransportRequest {
  url: string;
  method: "GET";
  headers: Record<string, string>;
  maxBytes: number;
  redirect: WebFetchRedirectPolicy;
}

export interface WebFetchTransportResponse {
  status: number;
  statusText?: string;
  headers?: Record<string, string>;
  body: string | Uint8Array;
  finalUrl?: string;
}

export interface WebFetchTransport {
  fetch(request: WebFetchTransportRequest): Promise<WebFetchTransportResponse> | WebFetchTransportResponse;
}

export type WebSearchResult = JsonObject & {
  title: string;
  url: string;
  snippet?: string;
  source?: string;
  publishedAt?: string;
};

export type WebSearchRequest = JsonObject & {
  query: string;
  maxResults: number;
};

export type WebSearchResponse = JsonObject & {
  providerName: string;
  results: WebSearchResult[];
};

export interface WebSearchProvider {
  readonly name: string;
  search(
    request: WebSearchRequest,
    context?: WebSearchProviderSearchContext
  ): Promise<WebSearchResponse> | WebSearchResponse;
}

export interface WebSearchProviderSearchContext {
  signal?: AbortSignal;
}

export interface WebSearchToolOptions {
  provider: WebSearchProvider;
  defaultMaxResults?: number;
  absoluteMaxResults?: number;
}

export type ShellToolPlatform = "posix" | "win32";

export type ShellToolShell = "cmd" | "powershell" | "sh";

export interface ShellExecutorRequest {
  command: string;
  cwd: string;
  env: Record<string, string>;
  timeoutMs: number;
  shell: ShellToolShell;
  platform: ShellToolPlatform;
  maxStdoutBytes: number;
  maxStderrBytes: number;
  signal?: AbortSignal;
}

export type ShellExecutorStatus = "completed" | "timed_out";

export interface ShellExecutorResult {
  status: ShellExecutorStatus;
  exitCode: number | null;
  signal: string | null;
  stdout: string;
  stderr: string;
  stdoutBytes: number;
  stderrBytes: number;
  stdoutTruncated: boolean;
  stderrTruncated: boolean;
}

export interface ShellExecutor {
  execute(request: ShellExecutorRequest): Promise<ShellExecutorResult> | ShellExecutorResult;
}

export interface ShellToolOptions {
  executor?: ShellExecutor;
  defaultCwd?: string;
  cwdRoots?: string[];
  baseEnv?: Record<string, string>;
  defaultTimeoutMs?: number;
  absoluteTimeoutMs?: number;
  defaultMaxOutputBytes?: number;
  absoluteMaxOutputBytes?: number;
  platform?: ShellToolPlatform;
  defaultShell?: ShellToolShell;
}

type ReadFileToolInput = JsonObject & {
  path: string;
  maxBytes?: number;
  encoding?: "utf8";
};

type ReadFileToolOutput = JsonObject & {
  path: string;
  normalizedPath: string;
  content: string;
  bytesRead: number;
  truncated: boolean;
};

type WriteFileMode = "create" | "overwrite";

type WriteFileToolInput = JsonObject & {
  path: string;
  content: string;
  mode?: WriteFileMode;
  encoding?: "utf8";
};

type WriteFileToolOutput = JsonObject & {
  path: string;
  normalizedPath: string;
  operation: "write";
  bytesWritten: number;
};

type WebFetchToolInput = JsonObject & {
  url: string;
  method?: "GET";
  headers?: Record<string, string>;
  maxBytes?: number;
  redirect?: WebFetchRedirectPolicy;
};

type WebFetchToolOutput = JsonObject & {
  url: string;
  status: number;
  body: string;
  bytesRead: number;
  truncated: boolean;
  method: "GET";
  redirect: WebFetchRedirectPolicy;
  statusText?: string;
  finalUrl?: string;
};

type WebSearchToolInput = JsonObject & {
  query: string;
  maxResults?: number;
};

type WebSearchToolOutput = JsonObject & {
  providerName: string;
  queryLength: number;
  maxResults: number;
  resultCount: number;
  results: WebSearchResult[];
};

type ShellToolInput = JsonObject & {
  command: string;
  cwd?: string;
  env?: Record<string, string>;
  timeoutMs?: number;
  maxOutputBytes?: number;
  shell?: ShellToolShell;
};

type ShellToolOutput = JsonObject & ShellExecutorResult;

export type ToolSchemaKind = "json" | "object" | "array" | "string" | "number" | "integer" | "boolean" | "null";

export interface ToolSchemaDescriptor {
  name: string;
  kind: ToolSchemaKind;
  description?: string;
  metadata?: Record<string, JsonValue>;
}

export interface ToolSchema<T extends JsonValue = JsonValue> extends ToolSchemaDescriptor {
  validate(value: unknown): Result<T>;
}

export interface ToolSchemaOptions<T extends JsonValue = JsonValue> extends ToolSchemaDescriptor {
  validate(value: unknown): Result<T>;
}

export interface ToolInvocationRequest<Input = unknown> {
  toolName: ToolName;
  input: Input;
  metadata?: Record<string, JsonValue>;
}

export interface NormalizedToolInvocationRequest<Input extends JsonValue = JsonValue> {
  toolName: ToolName;
  input: Input;
  metadata: Record<string, JsonValue>;
}

export interface ToolInvocationResponse<Output extends JsonValue = JsonValue> {
  toolName: ToolName;
  output: Output;
  metadata: JsonObject;
}

export type ToolInvocationResult<Output extends JsonValue = JsonValue> = Result<ToolInvocationResponse<Output>>;

export interface ToolDefinition<Input extends JsonValue = JsonValue, Output extends JsonValue = JsonValue> {
  name: ToolName;
  description: string;
  inputSchema: ToolSchema<Input>;
  outputSchema: ToolSchema<Output>;
  requiredPermissions: PermissionAction[];
  execute(input: Input, context: ToolExecutionContext): Promise<Output> | Output;
}

export interface RegisteredTool {
  name: ToolName;
  description: string;
  inputSchema: ToolSchemaDescriptor;
  outputSchema: ToolSchemaDescriptor;
  requiredPermissions: readonly PermissionAction[];
}

function toolSchemaError(code: "tool.invalid_input" | "tool.invalid_output", message: string, context: JsonObject): Result<never> {
  return err(
    new AppError({
      code,
      message,
      context
    })
  );
}

export function createToolSchema<T extends JsonValue>(options: ToolSchemaOptions<T>): ToolSchema<T> {
  return {
    name: options.name,
    kind: options.kind,
    ...(options.description !== undefined ? { description: options.description } : {}),
    ...(options.metadata !== undefined ? { metadata: options.metadata } : {}),
    validate: options.validate
  };
}

export function describeToolSchema(schema: ToolSchema): ToolSchemaDescriptor {
  return {
    name: schema.name,
    kind: schema.kind,
    ...(schema.description !== undefined ? { description: schema.description } : {}),
    ...(schema.metadata !== undefined ? { metadata: schema.metadata } : {})
  };
}

function describeToolSchemaForMetadata(schema: ToolSchema): JsonObject {
  const descriptor: JsonObject = {
    name: schema.name,
    kind: schema.kind
  };

  if (schema.description !== undefined) {
    descriptor.description = schema.description;
  }

  if (schema.metadata !== undefined) {
    descriptor.metadata = schema.metadata;
  }

  return descriptor;
}

export function jsonValueToolSchema(name = "json-value"): ToolSchema<JsonValue> {
  return createToolSchema({
    name,
    kind: "json",
    description: "Any JSON-safe value.",
    validate(value) {
      if (!isJsonValue(value)) {
        return toolSchemaError("tool.invalid_input", "Tool value must be JSON-safe", {
          schemaName: name
        });
      }

      return ok(value);
    }
  });
}

export function jsonObjectToolSchema(name = "json-object"): ToolSchema<JsonObject> {
  return createToolSchema({
    name,
    kind: "object",
    description: "A JSON-safe object.",
    validate(value) {
      if (!isJsonObject(value)) {
        return toolSchemaError("tool.invalid_input", "Tool value must be a JSON-safe object", {
          schemaName: name
        });
      }

      return ok(value);
    }
  });
}

const READ_FILE_TOOL_NAME = toolName("filesystem.read_file");
const WRITE_FILE_TOOL_NAME = toolName("filesystem.write_file");
const WEB_FETCH_TOOL_NAME = toolName("web.fetch");
const WEB_SEARCH_TOOL_NAME = toolName("web.search");
const SHELL_TOOL_NAME = toolName("shell.execute");
const DEFAULT_READ_FILE_MAX_BYTES = 64 * 1024;
const ABSOLUTE_READ_FILE_MAX_BYTES = 1024 * 1024;
const ABSOLUTE_WRITE_FILE_MAX_BYTES = 1024 * 1024;
const DEFAULT_WEB_FETCH_MAX_BYTES = 64 * 1024;
const ABSOLUTE_WEB_FETCH_MAX_BYTES = 1024 * 1024;
const DEFAULT_WEB_SEARCH_MAX_RESULTS = 5;
const ABSOLUTE_WEB_SEARCH_MAX_RESULTS = 20;
const DEFAULT_SHELL_TIMEOUT_MS = 30_000;
const ABSOLUTE_SHELL_TIMEOUT_MS = 5 * 60_000;
const DEFAULT_SHELL_MAX_OUTPUT_BYTES = 64 * 1024;
const ABSOLUTE_SHELL_MAX_OUTPUT_BYTES = 1024 * 1024;
const WEB_SEARCH_MAX_QUERY_CHARS = 512;
const WEB_SEARCH_MAX_PROVIDER_NAME_CHARS = 120;
const WEB_SEARCH_MAX_TITLE_CHARS = 300;
const WEB_SEARCH_MAX_URL_CHARS = 2048;
const WEB_SEARCH_MAX_SNIPPET_CHARS = 1000;
const WEB_SEARCH_MAX_SOURCE_CHARS = 120;
const WEB_SEARCH_MAX_PUBLISHED_AT_CHARS = 80;
const READ_FILE_INPUT_KEYS = new Set(["path", "maxBytes", "encoding"]);
const WRITE_FILE_INPUT_KEYS = new Set(["path", "content", "mode", "encoding"]);
const WEB_FETCH_INPUT_KEYS = new Set(["url", "method", "headers", "maxBytes", "redirect"]);
const WEB_SEARCH_INPUT_KEYS = new Set(["query", "maxResults"]);
const SHELL_INPUT_KEYS = new Set(["command", "cwd", "env", "timeoutMs", "maxOutputBytes", "shell"]);
const WEB_FETCH_ALLOWED_PROTOCOLS = new Set(["http:", "https:"]);
const WEB_FETCH_SAFE_TEXT_CONTENT_TYPES = [
  "application/javascript",
  "application/json",
  "application/ld+json",
  "application/xml",
  "application/xhtml+xml",
  "text/"
];
const WEB_FETCH_HEADER_NAME_PATTERN = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/u;
const WEB_FETCH_MAX_HEADER_COUNT = 20;
const WEB_FETCH_MAX_HEADER_NAME_BYTES = 128;
const WEB_FETCH_MAX_HEADER_VALUE_BYTES = 4096;

const DEFAULT_READ_FILE_ACCESS: ReadFileToolAccess = {
  async readBytes(filePath, byteLimit) {
    const handle = await open(filePath, "r");
    try {
      const buffer = Buffer.alloc(byteLimit);
      const { bytesRead } = await handle.read(buffer, 0, byteLimit, 0);
      return buffer.subarray(0, bytesRead);
    } finally {
      await handle.close();
    }
  }
};

const DEFAULT_WRITE_FILE_ACCESS: WriteFileToolAccess = {
  async directoryExists(directoryPath) {
    try {
      const stats = await stat(directoryPath);
      return stats.isDirectory();
    } catch {
      return false;
    }
  },
  async fileExists(filePath) {
    try {
      const stats = await stat(filePath);
      return stats.isFile();
    } catch {
      return false;
    }
  },
  async createFile(filePath, content, encoding) {
    const handle = await open(filePath, "wx");
    try {
      await handle.writeFile(content, encoding);
    } finally {
      await handle.close();
    }
  },
  async overwriteFile(filePath, content, encoding, temporaryPath) {
    try {
      await writeFile(temporaryPath, content, {
        encoding,
        flag: "wx"
      });
      await rename(temporaryPath, filePath);
    } catch (error) {
      await rm(temporaryPath, {
        force: true
      });
      throw error;
    }
  }
};

const DEFAULT_WEB_FETCH_TRANSPORT: WebFetchTransport = {
  async fetch(request) {
    const response = await fetch(request.url, {
      method: request.method,
      headers: request.headers,
      redirect: request.redirect
    });
    const body = new Uint8Array(await response.arrayBuffer());
    const headers: Record<string, string> = {};

    response.headers.forEach((value, key) => {
      headers[key] = value;
    });

    return {
      status: response.status,
      statusText: response.statusText,
      headers,
      body,
      finalUrl: response.url
    };
  }
};

function readFileToolError(message: string, context: JsonObject): Result<never> {
  return toolSchemaError("tool.invalid_input", message, context);
}

function validateReadFileMaxBytes(value: unknown, absoluteMaxBytes: number): Result<number | undefined> {
  if (value === undefined) {
    return ok(undefined);
  }

  if (typeof value !== "number" || !Number.isInteger(value) || !Number.isFinite(value) || value <= 0) {
    return readFileToolError("Read file maxBytes must be a positive integer when provided", {
      field: "maxBytes"
    });
  }

  if (value > absoluteMaxBytes) {
    return readFileToolError("Read file maxBytes exceeds the configured maximum", {
      field: "maxBytes",
      maxBytes: value,
      absoluteMaxBytes
    });
  }

  return ok(value);
}

function validateWriteFileContent(value: unknown, absoluteMaxBytes: number): Result<{
  content: string;
  bytesWritten: number;
}> {
  if (typeof value !== "string") {
    return readFileToolError("Write file content must be a string", {
      field: "content"
    });
  }

  const bytesWritten = Buffer.byteLength(value, "utf8");
  if (bytesWritten > absoluteMaxBytes) {
    return readFileToolError("Write file content exceeds the configured maximum", {
      field: "content",
      bytesWritten,
      absoluteMaxBytes
    });
  }

  return ok({
    content: value,
    bytesWritten
  });
}

function webFetchToolError(message: string, context: JsonObject): Result<never> {
  return toolSchemaError("tool.invalid_input", message, context);
}

function sanitizeUrlForAudit(value: string): string {
  try {
    const parsed = new URL(value);
    parsed.username = "";
    parsed.password = "";
    parsed.search = "";
    parsed.hash = "";
    return parsed.href;
  } catch {
    return value;
  }
}

function validateWebFetchUrl(value: unknown): Result<string> {
  if (typeof value !== "string" || value.trim().length === 0) {
    return webFetchToolError("Web fetch url must be a non-empty string", {
      field: "url"
    });
  }

  if (value.includes("\0")) {
    return webFetchToolError("Web fetch url must not contain NUL bytes", {
      field: "url"
    });
  }

  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    return webFetchToolError("Web fetch url must be a valid URL", {
      field: "url"
    });
  }

  if (!WEB_FETCH_ALLOWED_PROTOCOLS.has(parsed.protocol)) {
    return webFetchToolError("Web fetch url protocol is not allowed", {
      field: "url",
      protocol: parsed.protocol
    });
  }

  if (parsed.username.length > 0 || parsed.password.length > 0) {
    return webFetchToolError("Web fetch url must not include credentials", {
      field: "url"
    });
  }

  return ok(parsed.href);
}

function validateWebFetchMaxBytes(value: unknown, absoluteMaxBytes: number): Result<number | undefined> {
  if (value === undefined) {
    return ok(undefined);
  }

  if (typeof value !== "number" || !Number.isInteger(value) || !Number.isFinite(value) || value <= 0) {
    return webFetchToolError("Web fetch maxBytes must be a positive integer when provided", {
      field: "maxBytes"
    });
  }

  if (value > absoluteMaxBytes) {
    return webFetchToolError("Web fetch maxBytes exceeds the configured maximum", {
      field: "maxBytes",
      maxBytes: value,
      absoluteMaxBytes
    });
  }

  return ok(value);
}

function validateWebFetchMethod(value: unknown): Result<"GET" | undefined> {
  if (value === undefined) {
    return ok(undefined);
  }

  if (value !== "GET") {
    return webFetchToolError("Web fetch method must be GET when provided", {
      field: "method"
    });
  }

  return ok("GET");
}

function validateWebFetchRedirect(value: unknown): Result<WebFetchRedirectPolicy | undefined> {
  if (value === undefined) {
    return ok(undefined);
  }

  if (value !== "error" && value !== "follow") {
    return webFetchToolError("Web fetch redirect must be error or follow when provided", {
      field: "redirect"
    });
  }

  return ok(value);
}

function validateWebFetchHeaders(value: unknown): Result<Record<string, string> | undefined> {
  if (value === undefined) {
    return ok(undefined);
  }

  if (!isJsonObject(value)) {
    return webFetchToolError("Web fetch headers must be an object with string values", {
      field: "headers"
    });
  }

  const entries = Object.entries(value);
  if (entries.length > WEB_FETCH_MAX_HEADER_COUNT) {
    return webFetchToolError("Web fetch headers exceed the configured maximum count", {
      field: "headers",
      count: entries.length,
      maxHeaderCount: WEB_FETCH_MAX_HEADER_COUNT
    });
  }

  const headers: Record<string, string> = {};
  for (const [key, headerValue] of entries.sort(([left], [right]) => left.localeCompare(right))) {
    if (!WEB_FETCH_HEADER_NAME_PATTERN.test(key)) {
      return webFetchToolError("Web fetch header name is invalid", {
        field: "headers",
        header: key
      });
    }

    if (Buffer.byteLength(key, "utf8") > WEB_FETCH_MAX_HEADER_NAME_BYTES) {
      return webFetchToolError("Web fetch header name exceeds the configured maximum", {
        field: "headers",
        header: key
      });
    }

    if (typeof headerValue !== "string") {
      return webFetchToolError("Web fetch header values must be strings", {
        field: "headers",
        header: key
      });
    }

    if (/[\0\r\n]/u.test(headerValue)) {
      return webFetchToolError("Web fetch header values must not contain NUL bytes or newlines", {
        field: "headers",
        header: key
      });
    }

    if (Buffer.byteLength(headerValue, "utf8") > WEB_FETCH_MAX_HEADER_VALUE_BYTES) {
      return webFetchToolError("Web fetch header value exceeds the configured maximum", {
        field: "headers",
        header: key
      });
    }

    headers[key] = headerValue;
  }

  return ok(headers);
}

function webSearchToolError(message: string, context: JsonObject): Result<never> {
  return toolSchemaError("tool.invalid_input", message, context);
}

function validateWebSearchQuery(value: unknown): Result<string> {
  if (typeof value !== "string" || value.trim().length === 0) {
    return webSearchToolError("Web search query must be a non-empty string", {
      field: "query"
    });
  }

  if (value.includes("\0")) {
    return webSearchToolError("Web search query must not contain NUL bytes", {
      field: "query"
    });
  }

  const query = value.trim();
  if (query.length > WEB_SEARCH_MAX_QUERY_CHARS) {
    return webSearchToolError("Web search query exceeds the configured maximum length", {
      field: "query",
      queryLength: query.length,
      maxQueryChars: WEB_SEARCH_MAX_QUERY_CHARS
    });
  }

  return ok(query);
}

function validateWebSearchMaxResults(value: unknown, absoluteMaxResults: number): Result<number | undefined> {
  if (value === undefined) {
    return ok(undefined);
  }

  if (typeof value !== "number" || !Number.isInteger(value) || !Number.isFinite(value) || value <= 0) {
    return webSearchToolError("Web search maxResults must be a positive integer when provided", {
      field: "maxResults"
    });
  }

  if (value > absoluteMaxResults) {
    return webSearchToolError("Web search maxResults exceeds the configured maximum", {
      field: "maxResults",
      maxResults: value,
      absoluteMaxResults
    });
  }

  return ok(value);
}

function validateWebSearchProviderName(value: unknown): Result<string> {
  if (typeof value !== "string" || value.trim().length === 0) {
    return webSearchToolError("Web search provider name must be a non-empty string", {
      field: "provider.name"
    });
  }

  if (value.includes("\0")) {
    return webSearchToolError("Web search provider name must not contain NUL bytes", {
      field: "provider.name"
    });
  }

  const providerName = value.trim();
  if (providerName.length > WEB_SEARCH_MAX_PROVIDER_NAME_CHARS) {
    return webSearchToolError("Web search provider name exceeds the configured maximum length", {
      field: "provider.name",
      providerNameLength: providerName.length,
      maxProviderNameChars: WEB_SEARCH_MAX_PROVIDER_NAME_CHARS
    });
  }

  return ok(providerName);
}

function shellToolError(message: string, context: JsonObject): Result<never> {
  return toolSchemaError("tool.invalid_input", message, context);
}

function inferShellPlatform(): ShellToolPlatform {
  return process.platform === "win32" ? "win32" : "posix";
}

function defaultShellForPlatform(platform: ShellToolPlatform): ShellToolShell {
  return platform === "win32" ? "powershell" : "sh";
}

function validateShellChoice(value: unknown, platform: ShellToolPlatform): Result<ShellToolShell | undefined> {
  if (value === undefined) {
    return ok(undefined);
  }

  if (value !== "cmd" && value !== "powershell" && value !== "sh") {
    return shellToolError("Shell tool shell must be cmd, powershell, or sh when provided", {
      field: "shell"
    });
  }

  if (platform === "win32" && value === "sh") {
    return shellToolError("Shell tool shell must be cmd or powershell on Windows", {
      field: "shell",
      platform
    });
  }

  if (platform === "posix" && value !== "sh") {
    return shellToolError("Shell tool shell must be sh on POSIX platforms", {
      field: "shell",
      platform
    });
  }

  return ok(value);
}

function validateShellOutputBytes(value: unknown, absoluteMaxOutputBytes: number): Result<number | undefined> {
  if (value === undefined) {
    return ok(undefined);
  }

  if (typeof value !== "number" || !Number.isInteger(value) || !Number.isFinite(value) || value <= 0) {
    return shellToolError("Shell maxOutputBytes must be a positive integer when provided", {
      field: "maxOutputBytes"
    });
  }

  if (value > absoluteMaxOutputBytes) {
    return shellToolError("Shell maxOutputBytes exceeds the configured maximum", {
      field: "maxOutputBytes",
      maxOutputBytes: value,
      absoluteMaxOutputBytes
    });
  }

  return ok(value);
}

function normalizeShellPositiveInteger(value: number | undefined, fallback: number, label: string): number {
  const candidate = value ?? fallback;
  if (!Number.isInteger(candidate) || !Number.isFinite(candidate) || candidate <= 0) {
    throw new AppError({
      code: "tool.invalid_input",
      message: `Shell ${label} must be a positive integer`
    });
  }

  return candidate;
}

function normalizeShellCwdPath(
  cwd: string,
  platform: ShellToolPlatform,
  defaultCwd: string,
  field: string
): Result<string> {
  const pathApi = getPathApi(platform);
  const validated = validateFilesystemPathString(cwd, field, platform);
  if (!validated.ok) {
    return shellToolError("Shell cwd path is invalid", {
      field,
      validationCode: validated.error.code
    });
  }

  const resolved = pathApi.isAbsolute(cwd) ? cwd : pathApi.resolve(defaultCwd, cwd);
  const normalized = stripTrailingSeparators(pathApi.normalize(pathApi.resolve(resolved)), pathApi);

  if (!pathApi.isAbsolute(normalized)) {
    return shellToolError("Shell cwd must resolve to an absolute path", {
      field
    });
  }

  return ok(normalized);
}

function normalizeShellCwdRoots(
  roots: string[],
  platform: ShellToolPlatform,
  defaultCwd: string
): Result<NormalizedFilesystemRoot[]> {
  if (roots.length === 0) {
    return shellToolError("Shell cwdRoots must include at least one root", {
      field: "cwdRoots"
    });
  }

  const pathApi = getPathApi(platform);
  const normalizedRoots: NormalizedFilesystemRoot[] = [];
  for (const root of roots) {
    const normalized = normalizeShellCwdPath(root, platform, defaultCwd, "cwdRoots");
    if (!normalized.ok) {
      return normalized;
    }

    normalizedRoots.push({
      normalizedPath: normalized.value,
      comparisonPath: normalizeForComparison(normalized.value, platform, pathApi)
    });
  }

  return ok(normalizedRoots);
}

function isShellCwdInRoots(
  cwd: string,
  roots: readonly NormalizedFilesystemRoot[],
  platform: ShellToolPlatform
): boolean {
  const pathApi = getPathApi(platform);
  const comparisonPath = normalizeForComparison(cwd, platform, pathApi);
  return roots.some((root) => isSameOrChildPath(comparisonPath, root.comparisonPath, pathApi));
}

function normalizeShellToolOptions(options: ShellToolOptions): {
  defaultCwd: string;
  cwdRoots: NormalizedFilesystemRoot[];
  baseEnv: Record<string, string>;
  defaultTimeoutMs: number;
  absoluteTimeoutMs: number;
  defaultMaxOutputBytes: number;
  absoluteMaxOutputBytes: number;
  platform: ShellToolPlatform;
  defaultShell: ShellToolShell;
} {
  const platform = options.platform ?? inferShellPlatform();
  const defaultShell = options.defaultShell ?? defaultShellForPlatform(platform);
  const defaultShellResult = validateShellChoice(defaultShell, platform);
  if (!defaultShellResult.ok || defaultShellResult.value === undefined) {
    throw defaultShellResult.ok
      ? new AppError({
          code: "tool.invalid_input",
          message: "Shell default shell is invalid"
        })
      : defaultShellResult.error;
  }

  const cwdSeed = options.defaultCwd ?? process.cwd();
  const defaultCwd = normalizeShellCwdPath(cwdSeed, platform, process.cwd(), "defaultCwd");
  if (!defaultCwd.ok) {
    throw defaultCwd.error;
  }

  const cwdRoots = normalizeShellCwdRoots(options.cwdRoots ?? [defaultCwd.value], platform, defaultCwd.value);
  if (!cwdRoots.ok) {
    throw cwdRoots.error;
  }

  if (!isShellCwdInRoots(defaultCwd.value, cwdRoots.value, platform)) {
    throw new AppError({
      code: "tool.invalid_input",
      message: "Shell defaultCwd must be within cwdRoots",
      context: {
        defaultCwd: defaultCwd.value,
        cwdRoots: cwdRoots.value.map((root) => root.normalizedPath)
      }
    });
  }

  const baseEnvRequest = validateShellExecutionRequest({
    command: "noop",
    env: options.baseEnv ?? {}
  });
  if (!baseEnvRequest.ok) {
    throw baseEnvRequest.error;
  }

  const absoluteTimeoutMs = normalizeShellPositiveInteger(
    options.absoluteTimeoutMs,
    ABSOLUTE_SHELL_TIMEOUT_MS,
    "absoluteTimeoutMs"
  );
  const defaultTimeoutMs = normalizeShellPositiveInteger(
    options.defaultTimeoutMs,
    DEFAULT_SHELL_TIMEOUT_MS,
    "defaultTimeoutMs"
  );
  if (defaultTimeoutMs > absoluteTimeoutMs) {
    throw new AppError({
      code: "tool.invalid_input",
      message: "Shell defaultTimeoutMs must not exceed absoluteTimeoutMs"
    });
  }

  const absoluteMaxOutputBytes = normalizeShellPositiveInteger(
    options.absoluteMaxOutputBytes,
    ABSOLUTE_SHELL_MAX_OUTPUT_BYTES,
    "absoluteMaxOutputBytes"
  );
  const defaultMaxOutputBytes = normalizeShellPositiveInteger(
    options.defaultMaxOutputBytes,
    DEFAULT_SHELL_MAX_OUTPUT_BYTES,
    "defaultMaxOutputBytes"
  );
  if (defaultMaxOutputBytes > absoluteMaxOutputBytes) {
    throw new AppError({
      code: "tool.invalid_input",
      message: "Shell defaultMaxOutputBytes must not exceed absoluteMaxOutputBytes"
    });
  }

  return {
    defaultCwd: defaultCwd.value,
    cwdRoots: cwdRoots.value,
    baseEnv: baseEnvRequest.value.env,
    defaultTimeoutMs,
    absoluteTimeoutMs,
    defaultMaxOutputBytes,
    absoluteMaxOutputBytes,
    platform,
    defaultShell
  };
}

function getWindowsSystemRoot(): string {
  return process.env.SystemRoot ?? process.env.WINDIR ?? "C:\\Windows";
}

function createShellSpawnCommand(shell: ShellToolShell, command: string): {
  file: string;
  args: string[];
} {
  if (shell === "cmd") {
    return {
      file: path.win32.join(getWindowsSystemRoot(), "System32", "cmd.exe"),
      args: ["/d", "/s", "/c", command]
    };
  }

  if (shell === "powershell") {
    return {
      file: path.win32.join(getWindowsSystemRoot(), "System32", "WindowsPowerShell", "v1.0", "powershell.exe"),
      args: ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", command]
    };
  }

  return {
    file: "/bin/sh",
    args: ["-c", command]
  };
}

function createShellProcessEnv(baseEnv: Record<string, string>, env: Record<string, string>): Record<string, string> {
  return {
    ...baseEnv,
    ...env
  };
}

function appendLimitedChunk(
  chunks: Buffer[],
  currentBytes: number,
  chunk: Buffer,
  maxBytes: number
): {
  bytes: number;
  truncated: boolean;
} {
  if (currentBytes >= maxBytes) {
    return {
      bytes: currentBytes,
      truncated: chunk.length > 0
    };
  }

  const remaining = maxBytes - currentBytes;
  if (chunk.length <= remaining) {
    chunks.push(chunk);
    return {
      bytes: currentBytes + chunk.length,
      truncated: false
    };
  }

  chunks.push(chunk.subarray(0, remaining));
  return {
    bytes: maxBytes,
    truncated: true
  };
}

const DEFAULT_SHELL_EXECUTOR: ShellExecutor = {
  execute(request) {
    return new Promise<ShellExecutorResult>((resolve, reject) => {
      const spawnCommand = createShellSpawnCommand(request.shell, request.command);
      const child = spawn(spawnCommand.file, spawnCommand.args, {
        cwd: request.cwd,
        env: request.env,
        windowsHide: true
      });
      const stdoutChunks: Buffer[] = [];
      const stderrChunks: Buffer[] = [];
      let stdoutBytes = 0;
      let stderrBytes = 0;
      let stdoutTruncated = false;
      let stderrTruncated = false;
      let timedOut = false;
      let settled = false;

      const finish = (result: ShellExecutorResult): void => {
        if (settled) {
          return;
        }

        settled = true;
        cleanup();
        resolve(result);
      };

      const fail = (error: unknown): void => {
        if (settled) {
          return;
        }

        settled = true;
        cleanup();
        reject(error);
      };

      const killChild = (): void => {
        if (child.killed) {
          return;
        }

        child.kill();
      };

      const timeout = setTimeout(() => {
        timedOut = true;
        killChild();
      }, request.timeoutMs);

      const onAbort = (): void => {
        timedOut = true;
        killChild();
      };

      const cleanup = (): void => {
        clearTimeout(timeout);
        request.signal?.removeEventListener("abort", onAbort);
      };

      if (request.signal?.aborted === true) {
        onAbort();
      } else {
        request.signal?.addEventListener("abort", onAbort, { once: true });
      }

      child.stdout.on("data", (chunk: Buffer) => {
        const appended = appendLimitedChunk(stdoutChunks, stdoutBytes, chunk, request.maxStdoutBytes);
        stdoutBytes = appended.bytes;
        stdoutTruncated = stdoutTruncated || appended.truncated;
      });

      child.stderr.on("data", (chunk: Buffer) => {
        const appended = appendLimitedChunk(stderrChunks, stderrBytes, chunk, request.maxStderrBytes);
        stderrBytes = appended.bytes;
        stderrTruncated = stderrTruncated || appended.truncated;
      });

      child.on("error", fail);
      child.on("close", (exitCode, signal) => {
        finish({
          status: timedOut ? "timed_out" : "completed",
          exitCode,
          signal,
          stdout: decodeUtf8(Buffer.concat(stdoutChunks)),
          stderr: decodeUtf8(Buffer.concat(stderrChunks)),
          stdoutBytes,
          stderrBytes,
          stdoutTruncated,
          stderrTruncated
        });
      });
    });
  }
};

function truncateText(value: string, maxChars: number): string {
  return value.length > maxChars ? value.slice(0, maxChars) : value;
}

function normalizeWebSearchResult(result: WebSearchResult): Result<WebSearchResult> {
  const title = typeof result.title === "string" ? result.title.trim() : "";
  const url = typeof result.url === "string" ? result.url.trim() : "";

  if (title.length === 0) {
    return webSearchToolError("Web search result title must be a non-empty string", {
      field: "result.title"
    });
  }

  if (url.length === 0 || url.includes("\0")) {
    return webSearchToolError("Web search result url must be a non-empty string without NUL bytes", {
      field: "result.url"
    });
  }

  if (url.length > WEB_SEARCH_MAX_URL_CHARS) {
    return webSearchToolError("Web search result url exceeds the configured maximum length", {
      field: "result.url",
      urlLength: url.length,
      maxUrlChars: WEB_SEARCH_MAX_URL_CHARS
    });
  }

  let parsedUrl: URL;
  try {
    parsedUrl = new URL(url);
  } catch {
    return webSearchToolError("Web search result url must be a valid URL", {
      field: "result.url"
    });
  }

  if (!WEB_FETCH_ALLOWED_PROTOCOLS.has(parsedUrl.protocol)) {
    return webSearchToolError("Web search result url protocol is not allowed", {
      field: "result.url",
      protocol: parsedUrl.protocol
    });
  }

  if (parsedUrl.username.length > 0 || parsedUrl.password.length > 0) {
    return webSearchToolError("Web search result url must not include credentials", {
      field: "result.url"
    });
  }

  const normalized: WebSearchResult = {
    title: truncateText(title, WEB_SEARCH_MAX_TITLE_CHARS),
    url: parsedUrl.href
  };

  if (result.snippet !== undefined) {
    if (typeof result.snippet !== "string") {
      return webSearchToolError("Web search result snippet must be a string when provided", {
        field: "result.snippet"
      });
    }

    normalized.snippet = truncateText(result.snippet, WEB_SEARCH_MAX_SNIPPET_CHARS);
  }

  if (result.source !== undefined) {
    if (typeof result.source !== "string") {
      return webSearchToolError("Web search result source must be a string when provided", {
        field: "result.source"
      });
    }

    normalized.source = truncateText(result.source.trim(), WEB_SEARCH_MAX_SOURCE_CHARS);
  }

  if (result.publishedAt !== undefined) {
    if (typeof result.publishedAt !== "string") {
      return webSearchToolError("Web search result publishedAt must be a string when provided", {
        field: "result.publishedAt"
      });
    }

    normalized.publishedAt = truncateText(result.publishedAt.trim(), WEB_SEARCH_MAX_PUBLISHED_AT_CHARS);
  }

  return ok(normalized);
}

function normalizeWebSearchProviderResponse(
  response: WebSearchResponse,
  providerName: string,
  maxResults: number
): Result<WebSearchResponse> {
  if (!isJsonObject(response) || !Array.isArray(response.results)) {
    return webSearchToolError("Web search provider response must contain a results array", {
      schemaName: "web.search.output"
    });
  }

  const responseProviderName = response.providerName ?? providerName;
  const validatedProviderName = validateWebSearchProviderName(responseProviderName);
  if (!validatedProviderName.ok) {
    return validatedProviderName;
  }

  const normalizedResults: WebSearchResult[] = [];
  for (const result of response.results.slice(0, maxResults)) {
    if (!isJsonObject(result)) {
      return webSearchToolError("Web search result must be a JSON-safe object", {
        schemaName: "web.search.output"
      });
    }

    const normalized = normalizeWebSearchResult(result as WebSearchResult);
    if (!normalized.ok) {
      return normalized;
    }

    normalizedResults.push(normalized.value);
  }

  return ok({
    providerName: validatedProviderName.value,
    results: normalizedResults
  });
}

function createReadFileInputSchema(options: {
  defaultMaxBytes: number;
  absoluteMaxBytes: number;
}): ToolSchema<ReadFileToolInput> {
  return createToolSchema({
    name: "filesystem.read_file.input",
    kind: "object",
    description: "Read-only filesystem input.",
    metadata: {
      defaultMaxBytes: options.defaultMaxBytes,
      absoluteMaxBytes: options.absoluteMaxBytes
    },
    validate(value) {
      if (!isJsonObject(value)) {
        return readFileToolError("Read file input must be a JSON-safe object", {
          schemaName: "filesystem.read_file.input"
        });
      }

      for (const key of Object.keys(value)) {
        if (!READ_FILE_INPUT_KEYS.has(key)) {
          return readFileToolError("Read file input contains an unknown field", {
            field: key
          });
        }
      }

      if (typeof value.path !== "string" || value.path.trim().length === 0) {
        return readFileToolError("Read file path must be a non-empty string", {
          field: "path"
        });
      }

      if (value.path.includes("\0")) {
        return readFileToolError("Read file path must not contain NUL bytes", {
          field: "path"
        });
      }

      const maxBytes = validateReadFileMaxBytes(value.maxBytes, options.absoluteMaxBytes);
      if (!maxBytes.ok) {
        return maxBytes;
      }

      if (value.encoding !== undefined && value.encoding !== "utf8") {
        return readFileToolError("Read file encoding must be utf8 when provided", {
          field: "encoding"
        });
      }

      const input: ReadFileToolInput = {
        path: value.path
      };

      if (maxBytes.value !== undefined) {
        input.maxBytes = maxBytes.value;
      }

      if (value.encoding !== undefined) {
        input.encoding = value.encoding;
      }

      return ok(input);
    }
  });
}

function createWriteFileInputSchema(options: {
  absoluteMaxBytes: number;
}): ToolSchema<WriteFileToolInput> {
  return createToolSchema({
    name: "filesystem.write_file.input",
    kind: "object",
    description: "Explicit-approval filesystem write input.",
    metadata: {
      defaultMode: "create",
      absoluteMaxBytes: options.absoluteMaxBytes
    },
    validate(value) {
      if (!isJsonObject(value)) {
        return readFileToolError("Write file input must be a JSON-safe object", {
          schemaName: "filesystem.write_file.input"
        });
      }

      for (const key of Object.keys(value)) {
        if (!WRITE_FILE_INPUT_KEYS.has(key)) {
          return readFileToolError("Write file input contains an unknown field", {
            field: key
          });
        }
      }

      if (typeof value.path !== "string" || value.path.trim().length === 0) {
        return readFileToolError("Write file path must be a non-empty string", {
          field: "path"
        });
      }

      if (value.path.includes("\0")) {
        return readFileToolError("Write file path must not contain NUL bytes", {
          field: "path"
        });
      }

      const content = validateWriteFileContent(value.content, options.absoluteMaxBytes);
      if (!content.ok) {
        return content;
      }

      if (value.mode !== undefined && value.mode !== "create" && value.mode !== "overwrite") {
        return readFileToolError("Write file mode must be create or overwrite when provided", {
          field: "mode"
        });
      }

      if (value.encoding !== undefined && value.encoding !== "utf8") {
        return readFileToolError("Write file encoding must be utf8 when provided", {
          field: "encoding"
        });
      }

      const input: WriteFileToolInput = {
        path: value.path,
        content: content.value.content
      };

      if (value.mode !== undefined) {
        input.mode = value.mode;
      }

      if (value.encoding !== undefined) {
        input.encoding = value.encoding;
      }

      return ok(input);
    }
  });
}

function createWebFetchInputSchema(options: {
  defaultMaxBytes: number;
  absoluteMaxBytes: number;
}): ToolSchema<WebFetchToolInput> {
  return createToolSchema({
    name: "web.fetch.input",
    kind: "object",
    description: "Explicit-consent HTTP(S) fetch input.",
    metadata: {
      defaultMethod: "GET",
      defaultMaxBytes: options.defaultMaxBytes,
      absoluteMaxBytes: options.absoluteMaxBytes,
      defaultRedirect: "error",
      allowedProtocols: ["http", "https"]
    },
    validate(value) {
      if (!isJsonObject(value)) {
        return webFetchToolError("Web fetch input must be a JSON-safe object", {
          schemaName: "web.fetch.input"
        });
      }

      for (const key of Object.keys(value)) {
        if (!WEB_FETCH_INPUT_KEYS.has(key)) {
          return webFetchToolError("Web fetch input contains an unknown field", {
            field: key
          });
        }
      }

      const url = validateWebFetchUrl(value.url);
      if (!url.ok) {
        return url;
      }

      const method = validateWebFetchMethod(value.method);
      if (!method.ok) {
        return method;
      }

      const maxBytes = validateWebFetchMaxBytes(value.maxBytes, options.absoluteMaxBytes);
      if (!maxBytes.ok) {
        return maxBytes;
      }

      const redirect = validateWebFetchRedirect(value.redirect);
      if (!redirect.ok) {
        return redirect;
      }

      const headers = validateWebFetchHeaders(value.headers);
      if (!headers.ok) {
        return headers;
      }

      const input: WebFetchToolInput = {
        url: url.value
      };

      if (method.value !== undefined) {
        input.method = method.value;
      }

      if (headers.value !== undefined) {
        input.headers = headers.value;
      }

      if (maxBytes.value !== undefined) {
        input.maxBytes = maxBytes.value;
      }

      if (redirect.value !== undefined) {
        input.redirect = redirect.value;
      }

      return ok(input);
    }
  });
}

function createWebSearchInputSchema(options: {
  defaultMaxResults: number;
  absoluteMaxResults: number;
}): ToolSchema<WebSearchToolInput> {
  return createToolSchema({
    name: "web.search.input",
    kind: "object",
    description: "Explicit-consent web search input.",
    metadata: {
      defaultMaxResults: options.defaultMaxResults,
      absoluteMaxResults: options.absoluteMaxResults,
      maxQueryChars: WEB_SEARCH_MAX_QUERY_CHARS
    },
    validate(value) {
      if (!isJsonObject(value)) {
        return webSearchToolError("Web search input must be a JSON-safe object", {
          schemaName: "web.search.input"
        });
      }

      for (const key of Object.keys(value)) {
        if (!WEB_SEARCH_INPUT_KEYS.has(key)) {
          return webSearchToolError("Web search input contains an unknown field", {
            field: key
          });
        }
      }

      const query = validateWebSearchQuery(value.query);
      if (!query.ok) {
        return query;
      }

      const maxResults = validateWebSearchMaxResults(value.maxResults, options.absoluteMaxResults);
      if (!maxResults.ok) {
        return maxResults;
      }

      const input: WebSearchToolInput = {
        query: query.value
      };

      if (maxResults.value !== undefined) {
        input.maxResults = maxResults.value;
      }

      return ok(input);
    }
  });
}

function createShellInputSchema(options: {
  defaultCwd: string;
  cwdRoots: readonly NormalizedFilesystemRoot[];
  defaultTimeoutMs: number;
  absoluteTimeoutMs: number;
  defaultMaxOutputBytes: number;
  absoluteMaxOutputBytes: number;
  platform: ShellToolPlatform;
  defaultShell: ShellToolShell;
}): ToolSchema<ShellToolInput> {
  return createToolSchema({
    name: "shell.execute.input",
    kind: "object",
    description: "Explicit-approval shell execution input.",
    metadata: {
      defaultCwd: options.defaultCwd,
      cwdRoots: options.cwdRoots.map((root) => root.normalizedPath),
      defaultTimeoutMs: options.defaultTimeoutMs,
      absoluteTimeoutMs: options.absoluteTimeoutMs,
      defaultMaxOutputBytes: options.defaultMaxOutputBytes,
      absoluteMaxOutputBytes: options.absoluteMaxOutputBytes,
      platform: options.platform,
      defaultShell: options.defaultShell,
      windowsShells: ["powershell", "cmd"],
      posixShells: ["sh"]
    },
    validate(value) {
      if (!isJsonObject(value)) {
        return shellToolError("Shell input must be a JSON-safe object", {
          schemaName: "shell.execute.input"
        });
      }

      for (const key of Object.keys(value)) {
        if (!SHELL_INPUT_KEYS.has(key)) {
          return shellToolError("Shell input contains an unknown field", {
            field: key
          });
        }
      }

      const shellRequest: {
        command: unknown;
        cwd?: unknown;
        env?: unknown;
        timeoutMs?: unknown;
      } = {
        command: value.command
      };

      if (value.cwd !== undefined) {
        shellRequest.cwd = value.cwd;
      }

      if (value.env !== undefined) {
        shellRequest.env = value.env;
      }

      if (value.timeoutMs !== undefined) {
        shellRequest.timeoutMs = value.timeoutMs;
      }

      const normalized = validateShellExecutionRequest(shellRequest);
      if (!normalized.ok) {
        return normalized;
      }

      const cwd = normalizeShellCwdPath(normalized.value.cwd ?? options.defaultCwd, options.platform, options.defaultCwd, "cwd");
      if (!cwd.ok) {
        return cwd;
      }

      if (!isShellCwdInRoots(cwd.value, options.cwdRoots, options.platform)) {
        return shellToolError("Shell cwd is outside approved roots", {
          field: "cwd",
          cwd: cwd.value,
          cwdRoots: options.cwdRoots.map((root) => root.normalizedPath)
        });
      }

      const timeoutMs = normalized.value.timeoutMs;
      if (timeoutMs !== undefined && timeoutMs > options.absoluteTimeoutMs) {
        return shellToolError("Shell timeoutMs exceeds the configured maximum", {
          field: "timeoutMs",
          timeoutMs,
          absoluteTimeoutMs: options.absoluteTimeoutMs
        });
      }

      const maxOutputBytes = validateShellOutputBytes(value.maxOutputBytes, options.absoluteMaxOutputBytes);
      if (!maxOutputBytes.ok) {
        return maxOutputBytes;
      }

      const shell = validateShellChoice(value.shell, options.platform);
      if (!shell.ok) {
        return shell;
      }

      const input: ShellToolInput = {
        command: normalized.value.command
      };

      if (value.cwd !== undefined) {
        input.cwd = cwd.value;
      }

      if (Object.keys(normalized.value.env).length > 0) {
        input.env = normalized.value.env;
      }

      if (timeoutMs !== undefined) {
        input.timeoutMs = timeoutMs;
      }

      if (maxOutputBytes.value !== undefined) {
        input.maxOutputBytes = maxOutputBytes.value;
      }

      if (shell.value !== undefined) {
        input.shell = shell.value;
      }

      return ok(input);
    }
  });
}

const readFileOutputSchema = createToolSchema<ReadFileToolOutput>({
  name: "filesystem.read_file.output",
  kind: "object",
  description: "Read-only filesystem output.",
  validate(value) {
    if (!isJsonObject(value)) {
      return toolSchemaError("tool.invalid_output", "Read file output must be a JSON-safe object", {
        schemaName: "filesystem.read_file.output"
      });
    }

    if (
      typeof value.path !== "string" ||
      typeof value.normalizedPath !== "string" ||
      typeof value.content !== "string" ||
      typeof value.bytesRead !== "number" ||
      !Number.isInteger(value.bytesRead) ||
      value.bytesRead < 0 ||
      typeof value.truncated !== "boolean"
    ) {
      return toolSchemaError("tool.invalid_output", "Read file output has an invalid shape", {
        schemaName: "filesystem.read_file.output"
      });
    }

    return ok({
      path: value.path,
      normalizedPath: value.normalizedPath,
      content: value.content,
      bytesRead: value.bytesRead,
      truncated: value.truncated
    });
  }
});

const writeFileOutputSchema = createToolSchema<WriteFileToolOutput>({
  name: "filesystem.write_file.output",
  kind: "object",
  description: "Explicit-approval filesystem write output.",
  validate(value) {
    if (!isJsonObject(value)) {
      return toolSchemaError("tool.invalid_output", "Write file output must be a JSON-safe object", {
        schemaName: "filesystem.write_file.output"
      });
    }

    if (
      typeof value.path !== "string" ||
      typeof value.normalizedPath !== "string" ||
      value.operation !== "write" ||
      typeof value.bytesWritten !== "number" ||
      !Number.isInteger(value.bytesWritten) ||
      value.bytesWritten < 0
    ) {
      return toolSchemaError("tool.invalid_output", "Write file output has an invalid shape", {
        schemaName: "filesystem.write_file.output"
      });
    }

    return ok({
      path: value.path,
      normalizedPath: value.normalizedPath,
      operation: "write",
      bytesWritten: value.bytesWritten
    });
  }
});

const webFetchOutputSchema = createToolSchema<WebFetchToolOutput>({
  name: "web.fetch.output",
  kind: "object",
  description: "Explicit-consent HTTP(S) fetch output.",
  validate(value) {
    if (!isJsonObject(value)) {
      return toolSchemaError("tool.invalid_output", "Web fetch output must be a JSON-safe object", {
        schemaName: "web.fetch.output"
      });
    }

    if (
      typeof value.url !== "string" ||
      value.method !== "GET" ||
      (value.redirect !== "error" && value.redirect !== "follow") ||
      typeof value.status !== "number" ||
      !Number.isInteger(value.status) ||
      value.status < 100 ||
      value.status > 999 ||
      typeof value.body !== "string" ||
      typeof value.bytesRead !== "number" ||
      !Number.isInteger(value.bytesRead) ||
      value.bytesRead < 0 ||
      typeof value.truncated !== "boolean"
    ) {
      return toolSchemaError("tool.invalid_output", "Web fetch output has an invalid shape", {
        schemaName: "web.fetch.output"
      });
    }

    const output: WebFetchToolOutput = {
      url: value.url,
      method: value.method,
      redirect: value.redirect,
      status: value.status,
      body: value.body,
      bytesRead: value.bytesRead,
      truncated: value.truncated
    };

    if (value.statusText !== undefined) {
      if (typeof value.statusText !== "string") {
        return toolSchemaError("tool.invalid_output", "Web fetch statusText must be a string when provided", {
          schemaName: "web.fetch.output"
        });
      }

      output.statusText = value.statusText;
    }

    if (value.finalUrl !== undefined) {
      if (typeof value.finalUrl !== "string") {
        return toolSchemaError("tool.invalid_output", "Web fetch finalUrl must be a string when provided", {
          schemaName: "web.fetch.output"
        });
      }

      output.finalUrl = value.finalUrl;
    }

    return ok(output);
  }
});

const webSearchOutputSchema = createToolSchema<WebSearchToolOutput>({
  name: "web.search.output",
  kind: "object",
  description: "Explicit-consent web search output.",
  validate(value) {
    if (!isJsonObject(value)) {
      return toolSchemaError("tool.invalid_output", "Web search output must be a JSON-safe object", {
        schemaName: "web.search.output"
      });
    }

    if (
      typeof value.providerName !== "string" ||
      typeof value.queryLength !== "number" ||
      !Number.isInteger(value.queryLength) ||
      value.queryLength < 0 ||
      typeof value.maxResults !== "number" ||
      !Number.isInteger(value.maxResults) ||
      value.maxResults <= 0 ||
      value.maxResults > ABSOLUTE_WEB_SEARCH_MAX_RESULTS ||
      typeof value.resultCount !== "number" ||
      !Number.isInteger(value.resultCount) ||
      value.resultCount < 0 ||
      !Array.isArray(value.results) ||
      value.results.length !== value.resultCount ||
      value.results.length > value.maxResults
    ) {
      return toolSchemaError("tool.invalid_output", "Web search output has an invalid shape", {
        schemaName: "web.search.output"
      });
    }

    const providerName = validateWebSearchProviderName(value.providerName);
    if (!providerName.ok) {
      return toolSchemaError("tool.invalid_output", "Web search output providerName is invalid", {
        schemaName: "web.search.output",
        validationCode: providerName.error.code
      });
    }

    const results: WebSearchResult[] = [];
    for (const result of value.results) {
      if (!isJsonObject(result)) {
        return toolSchemaError("tool.invalid_output", "Web search output result must be a JSON-safe object", {
          schemaName: "web.search.output"
        });
      }

      const normalized = normalizeWebSearchResult(result as WebSearchResult);
      if (!normalized.ok) {
        return toolSchemaError("tool.invalid_output", "Web search output result is invalid", {
          schemaName: "web.search.output",
          validationCode: normalized.error.code
        });
      }

      results.push(normalized.value);
    }

    return ok({
      providerName: providerName.value,
      queryLength: value.queryLength,
      maxResults: value.maxResults,
      resultCount: value.resultCount,
      results
    });
  }
});

const shellOutputSchema = createToolSchema<ShellToolOutput>({
  name: "shell.execute.output",
  kind: "object",
  description: "Explicit-approval shell execution output.",
  validate(value) {
    if (!isJsonObject(value)) {
      return toolSchemaError("tool.invalid_output", "Shell output must be a JSON-safe object", {
        schemaName: "shell.execute.output"
      });
    }

    if (
      (value.status !== "completed" && value.status !== "timed_out") ||
      (typeof value.exitCode !== "number" && value.exitCode !== null) ||
      (typeof value.exitCode === "number" && (!Number.isInteger(value.exitCode) || value.exitCode < 0)) ||
      (typeof value.signal !== "string" && value.signal !== null) ||
      typeof value.stdout !== "string" ||
      typeof value.stderr !== "string" ||
      typeof value.stdoutBytes !== "number" ||
      !Number.isInteger(value.stdoutBytes) ||
      value.stdoutBytes < 0 ||
      typeof value.stderrBytes !== "number" ||
      !Number.isInteger(value.stderrBytes) ||
      value.stderrBytes < 0 ||
      typeof value.stdoutTruncated !== "boolean" ||
      typeof value.stderrTruncated !== "boolean"
    ) {
      return toolSchemaError("tool.invalid_output", "Shell output has an invalid shape", {
        schemaName: "shell.execute.output"
      });
    }

    return ok({
      status: value.status,
      exitCode: value.exitCode,
      signal: value.signal,
      stdout: value.stdout,
      stderr: value.stderr,
      stdoutBytes: value.stdoutBytes,
      stderrBytes: value.stderrBytes,
      stdoutTruncated: value.stdoutTruncated,
      stderrTruncated: value.stderrTruncated
    });
  }
});

function normalizeReadFileLimit(options: ReadFileToolOptions): {
  defaultMaxBytes: number;
  absoluteMaxBytes: number;
} {
  const absoluteMaxBytes = options.absoluteMaxBytes ?? ABSOLUTE_READ_FILE_MAX_BYTES;
  const defaultMaxBytes = options.defaultMaxBytes ?? DEFAULT_READ_FILE_MAX_BYTES;

  if (!Number.isInteger(absoluteMaxBytes) || absoluteMaxBytes <= 0 || !Number.isFinite(absoluteMaxBytes)) {
    throw new AppError({
      code: "tool.invalid_input",
      message: "Read file absoluteMaxBytes must be a positive integer"
    });
  }

  if (!Number.isInteger(defaultMaxBytes) || defaultMaxBytes <= 0 || !Number.isFinite(defaultMaxBytes)) {
    throw new AppError({
      code: "tool.invalid_input",
      message: "Read file defaultMaxBytes must be a positive integer"
    });
  }

  if (defaultMaxBytes > absoluteMaxBytes) {
    throw new AppError({
      code: "tool.invalid_input",
      message: "Read file defaultMaxBytes must not exceed absoluteMaxBytes"
    });
  }

  return {
    defaultMaxBytes,
    absoluteMaxBytes
  };
}

function normalizeWebFetchLimit(options: WebFetchToolOptions): {
  defaultMaxBytes: number;
  absoluteMaxBytes: number;
} {
  const absoluteMaxBytes = options.absoluteMaxBytes ?? ABSOLUTE_WEB_FETCH_MAX_BYTES;
  const defaultMaxBytes = options.defaultMaxBytes ?? DEFAULT_WEB_FETCH_MAX_BYTES;

  if (!Number.isInteger(absoluteMaxBytes) || absoluteMaxBytes <= 0 || !Number.isFinite(absoluteMaxBytes)) {
    throw new AppError({
      code: "tool.invalid_input",
      message: "Web fetch absoluteMaxBytes must be a positive integer"
    });
  }

  if (!Number.isInteger(defaultMaxBytes) || defaultMaxBytes <= 0 || !Number.isFinite(defaultMaxBytes)) {
    throw new AppError({
      code: "tool.invalid_input",
      message: "Web fetch defaultMaxBytes must be a positive integer"
    });
  }

  if (absoluteMaxBytes > ABSOLUTE_WEB_FETCH_MAX_BYTES) {
    throw new AppError({
      code: "tool.invalid_input",
      message: "Web fetch absoluteMaxBytes must not exceed the hard maximum",
      context: {
        absoluteMaxBytes,
        hardMaxBytes: ABSOLUTE_WEB_FETCH_MAX_BYTES
      }
    });
  }

  if (defaultMaxBytes > absoluteMaxBytes) {
    throw new AppError({
      code: "tool.invalid_input",
      message: "Web fetch defaultMaxBytes must not exceed absoluteMaxBytes"
    });
  }

  return {
    defaultMaxBytes,
    absoluteMaxBytes
  };
}

function normalizeWebSearchLimit(options: WebSearchToolOptions): {
  defaultMaxResults: number;
  absoluteMaxResults: number;
} {
  const absoluteMaxResults = options.absoluteMaxResults ?? ABSOLUTE_WEB_SEARCH_MAX_RESULTS;
  const defaultMaxResults = options.defaultMaxResults ?? DEFAULT_WEB_SEARCH_MAX_RESULTS;

  if (!Number.isInteger(absoluteMaxResults) || absoluteMaxResults <= 0 || !Number.isFinite(absoluteMaxResults)) {
    throw new AppError({
      code: "tool.invalid_input",
      message: "Web search absoluteMaxResults must be a positive integer"
    });
  }

  if (!Number.isInteger(defaultMaxResults) || defaultMaxResults <= 0 || !Number.isFinite(defaultMaxResults)) {
    throw new AppError({
      code: "tool.invalid_input",
      message: "Web search defaultMaxResults must be a positive integer"
    });
  }

  if (absoluteMaxResults > ABSOLUTE_WEB_SEARCH_MAX_RESULTS) {
    throw new AppError({
      code: "tool.invalid_input",
      message: "Web search absoluteMaxResults must not exceed the hard maximum",
      context: {
        absoluteMaxResults,
        hardMaxResults: ABSOLUTE_WEB_SEARCH_MAX_RESULTS
      }
    });
  }

  if (defaultMaxResults > absoluteMaxResults) {
    throw new AppError({
      code: "tool.invalid_input",
      message: "Web search defaultMaxResults must not exceed absoluteMaxResults"
    });
  }

  return {
    defaultMaxResults,
    absoluteMaxResults
  };
}

function normalizeWriteFileLimit(options: WriteFileToolOptions): {
  absoluteMaxBytes: number;
} {
  const absoluteMaxBytes = options.absoluteMaxBytes ?? ABSOLUTE_WRITE_FILE_MAX_BYTES;

  if (!Number.isInteger(absoluteMaxBytes) || absoluteMaxBytes <= 0 || !Number.isFinite(absoluteMaxBytes)) {
    throw new AppError({
      code: "tool.invalid_input",
      message: "Write file absoluteMaxBytes must be a positive integer"
    });
  }

  return {
    absoluteMaxBytes
  };
}

function isLikelyBinary(buffer: Uint8Array): boolean {
  if (buffer.length === 0) {
    return false;
  }

  let suspiciousControlBytes = 0;

  for (const byte of buffer) {
    if (byte === 0) {
      return true;
    }

    const isAllowedControlByte = byte === 9 || byte === 10 || byte === 12 || byte === 13;
    if (byte < 32 && !isAllowedControlByte) {
      suspiciousControlBytes += 1;
    }
  }

  return suspiciousControlBytes / buffer.length > 0.3;
}

function decodeUtf8(buffer: Uint8Array): string {
  return new TextDecoder("utf-8", {
    fatal: false
  }).decode(buffer);
}

async function auditReadFileOperation(
  context: ToolExecutionContext,
  options: {
    decision: "allowed" | "denied" | "not_applicable";
    outcome: "succeeded" | "failed" | "denied";
    requestedPath: string;
    normalizedPath?: string;
    realPath?: string;
    maxBytes?: number;
    bytesRead?: number;
    truncated?: boolean;
    errorCode?: string;
  }
): Promise<void> {
  await appendAuditEvent(context.audit, {
    sourcePackage: "@dominic-nexus/tools",
    action: "filesystem.read",
    decision: options.decision,
    resource: {
      type: "file",
      id: options.normalizedPath ?? options.requestedPath,
      name: options.normalizedPath ?? options.requestedPath
    },
    outcome: options.outcome,
    metadata: {
      operation: "read",
      requestedPath: options.requestedPath,
      normalizedPath: options.normalizedPath ?? null,
      realPath: options.realPath ?? null,
      maxBytes: options.maxBytes ?? null,
      bytesRead: options.bytesRead ?? null,
      truncated: options.truncated ?? null,
      errorCode: options.errorCode ?? null
    }
  });
}

async function auditWriteFileOperation(
  context: ToolExecutionContext,
  options: {
    decision: "allowed" | "denied" | "not_applicable";
    outcome: "succeeded" | "failed" | "denied";
    requestedPath: string;
    normalizedPath?: string;
    mode: WriteFileMode;
    attemptedBytes: number;
    bytesWritten?: number;
    errorCode?: string;
  }
): Promise<void> {
  await appendAuditEvent(context.audit, {
    sourcePackage: "@dominic-nexus/tools",
    action: "filesystem.write",
    decision: options.decision,
    resource: {
      type: "file",
      id: options.normalizedPath ?? options.requestedPath,
      name: options.normalizedPath ?? options.requestedPath
    },
    outcome: options.outcome,
    metadata: {
      operation: "write",
      requestedPath: options.requestedPath,
      normalizedPath: options.normalizedPath ?? null,
      mode: options.mode,
      attemptedBytes: options.attemptedBytes,
      bytesWritten: options.bytesWritten ?? null,
      errorCode: options.errorCode ?? null
    }
  });
}

async function auditWebFetchOperation(
  context: ToolExecutionContext,
  options: {
    decision: "allowed" | "denied" | "not_applicable";
    outcome: "succeeded" | "failed" | "denied";
    requestedUrl: string;
    method: "GET";
    maxBytes: number;
    redirect: WebFetchRedirectPolicy;
    status?: number;
    statusText?: string | undefined;
    bytesRead?: number;
    truncated?: boolean;
    finalUrl?: string | undefined;
    errorCode?: string;
    headerNames?: string[];
  }
): Promise<void> {
  const sanitizedUrl = sanitizeUrlForAudit(options.requestedUrl);

  await appendAuditEvent(context.audit, {
    sourcePackage: "@dominic-nexus/tools",
    action: "web.fetch",
    decision: options.decision,
    resource: {
      type: "url",
      id: sanitizedUrl,
      name: sanitizedUrl
    },
    outcome: options.outcome,
    metadata: {
      operation: "fetch",
      requestedUrl: sanitizedUrl,
      method: options.method,
      maxBytes: options.maxBytes,
      redirect: options.redirect,
      status: options.status ?? null,
      statusText: options.statusText ?? null,
      bytesRead: options.bytesRead ?? null,
      truncated: options.truncated ?? null,
      finalUrl: options.finalUrl !== undefined ? sanitizeUrlForAudit(options.finalUrl) : null,
      errorCode: options.errorCode ?? null,
      headerNames: options.headerNames ?? []
    }
  });
}

async function auditWebSearchOperation(
  context: ToolExecutionContext,
  options: {
    decision: "allowed" | "denied" | "not_applicable";
    outcome: "succeeded" | "failed" | "denied";
    providerName: string;
    queryLength: number;
    maxResults: number;
    resultCount?: number;
    errorCode?: string;
  }
): Promise<void> {
  await appendAuditEvent(context.audit, {
    sourcePackage: "@dominic-nexus/tools",
    action: "web.search",
    decision: options.decision,
    resource: {
      type: "web_search_provider",
      id: options.providerName,
      name: options.providerName
    },
    outcome: options.outcome,
    metadata: {
      operation: "search",
      providerName: options.providerName,
      queryLength: options.queryLength,
      maxResults: options.maxResults,
      resultCount: options.resultCount ?? null,
      errorCode: options.errorCode ?? null
    }
  });
}

async function auditShellOperation(
  context: ToolExecutionContext,
  options: {
    decision: "allowed" | "denied" | "not_applicable";
    outcome: "succeeded" | "failed" | "denied";
    command: string;
    cwd: string;
    envKeys: string[];
    baseEnvKeys: string[];
    timeoutMs: number;
    maxOutputBytes: number;
    shell: ShellToolShell;
    platform: ShellToolPlatform;
    status?: ShellExecutorStatus;
    exitCode?: number | null;
    signal?: string | null;
    stdoutBytes?: number;
    stderrBytes?: number;
    stdoutTruncated?: boolean;
    stderrTruncated?: boolean;
    errorCode?: string;
  }
): Promise<void> {
  await appendAuditEvent(context.audit, {
    sourcePackage: "@dominic-nexus/tools",
    action: "shell.execute",
    decision: options.decision,
    resource: {
      type: "shell_command",
      id: options.command,
      name: options.command
    },
    outcome: options.outcome,
    metadata: {
      command: options.command,
      cwd: options.cwd,
      envKeys: options.envKeys,
      baseEnvKeys: options.baseEnvKeys,
      timeoutMs: options.timeoutMs,
      maxOutputBytes: options.maxOutputBytes,
      shell: options.shell,
      platform: options.platform,
      status: options.status ?? null,
      exitCode: options.exitCode ?? null,
      signal: options.signal ?? null,
      stdoutBytes: options.stdoutBytes ?? null,
      stderrBytes: options.stderrBytes ?? null,
      stdoutTruncated: options.stdoutTruncated ?? null,
      stderrTruncated: options.stderrTruncated ?? null,
      errorCode: options.errorCode ?? null
    }
  });
}

function createWriteFileExecutionError(message: string, context: JsonObject): AppError {
  return new AppError({
    code: "tool.execution_failed",
    message,
    context
  });
}

function createWebFetchExecutionError(message: string, context: JsonObject): AppError {
  return new AppError({
    code: "tool.execution_failed",
    message,
    context
  });
}

function isWebFetchContentTypeAllowed(value: string | undefined): boolean {
  if (value === undefined || value.trim().length === 0) {
    return true;
  }

  const contentType = value.split(";", 1)[0]?.trim().toLowerCase() ?? "";
  return WEB_FETCH_SAFE_TEXT_CONTENT_TYPES.some((allowed) =>
    allowed.endsWith("/") ? contentType.startsWith(allowed) : contentType === allowed
  );
}

function getHeaderCaseInsensitive(headers: Record<string, string> | undefined, name: string): string | undefined {
  if (headers === undefined) {
    return undefined;
  }

  const requested = name.toLowerCase();
  const match = Object.entries(headers).find(([key]) => key.toLowerCase() === requested);
  return match?.[1];
}

function bodyToBytes(body: string | Uint8Array): Uint8Array {
  return typeof body === "string" ? Buffer.from(body, "utf8") : body;
}

function validateWebFetchTransportResponse(response: WebFetchTransportResponse): void {
  if (!Number.isInteger(response.status) || response.status < 100 || response.status > 999) {
    throw createWebFetchExecutionError("Web fetch transport returned an invalid status", {
      status: response.status
    });
  }
}

function createTemporarySiblingPath(filePath: string): string {
  const pathApi = getPathApiForResolvedPath(filePath);
  const directory = pathApi.dirname(filePath);
  const basename = pathApi.basename(filePath);
  return pathApi.join(directory, `.${basename}.dominic-nexus-${process.pid}-${Date.now()}.tmp`);
}

function createReadFileTool(options: ReadFileToolOptions): ToolDefinition<ReadFileToolInput, ReadFileToolOutput> {
  const limits = normalizeReadFileLimit(options);
  const inputSchema = createReadFileInputSchema(limits);
  const access = options.access ?? DEFAULT_READ_FILE_ACCESS;

  return {
    name: READ_FILE_TOOL_NAME,
    description: "Reads a UTF-8 text file under approved filesystem roots.",
    inputSchema,
    outputSchema: readFileOutputSchema,
    requiredPermissions: ["filesystem.read"],
    async execute(input, context) {
      const maxBytes = input.maxBytes ?? limits.defaultMaxBytes;
      const authorizationRequest: FilesystemAuthorizationRequest = {
        path: input.path,
        policy: context.policy,
        reason: "Read file through filesystem.read_file tool",
        metadata: {
          ...(context.metadata ?? {}),
          operation: "read",
          requestedPath: input.path,
          maxBytes
        }
      };

      if (context.audit !== undefined) {
        authorizationRequest.audit = context.audit;
      }

      const authorization = await authorizeFilesystemRead(options.filesystem, authorizationRequest);

      if (!authorization.ok) {
        await auditReadFileOperation(context, {
          decision: authorization.error.code === "filesystem.permission_denied" ? "denied" : "not_applicable",
          outcome: authorization.error.code === "filesystem.permission_denied" ? "denied" : "failed",
          requestedPath: input.path,
          maxBytes,
          errorCode: authorization.error.code
        });
        throw authorization.error;
      }

      const resolved = authorization.value;
      let rawBytes: Uint8Array;

      try {
        rawBytes = await access.readBytes(resolved.normalizedPath, maxBytes + 1);
      } catch (error) {
        const appError = toAppError(error, {
          code: "tool.execution_failed",
          message: "Read file failed",
          context: {
            path: resolved.normalizedPath
          }
        });
        await auditReadFileOperation(context, {
          decision: "allowed",
          outcome: "failed",
          requestedPath: input.path,
          normalizedPath: resolved.normalizedPath,
          ...(resolved.realPath !== undefined ? { realPath: resolved.realPath } : {}),
          maxBytes,
          errorCode: appError.code
        });
        throw appError;
      }

      const truncated = rawBytes.length > maxBytes;
      const contentBytes = truncated ? rawBytes.subarray(0, maxBytes) : rawBytes;

      if (isLikelyBinary(contentBytes)) {
        const error = new AppError({
          code: "tool.execution_failed",
          message: "Read file refused likely binary content",
          context: {
            path: resolved.normalizedPath
          }
        });
        await auditReadFileOperation(context, {
          decision: "allowed",
          outcome: "failed",
          requestedPath: input.path,
          normalizedPath: resolved.normalizedPath,
          ...(resolved.realPath !== undefined ? { realPath: resolved.realPath } : {}),
          maxBytes,
          bytesRead: contentBytes.length,
          truncated,
          errorCode: error.code
        });
        throw error;
      }

      const output: ReadFileToolOutput = {
        path: input.path,
        normalizedPath: resolved.normalizedPath,
        content: decodeUtf8(contentBytes),
        bytesRead: contentBytes.length,
        truncated
      };

      await auditReadFileOperation(context, {
        decision: "allowed",
        outcome: "succeeded",
        requestedPath: input.path,
        normalizedPath: resolved.normalizedPath,
        ...(resolved.realPath !== undefined ? { realPath: resolved.realPath } : {}),
        maxBytes,
        bytesRead: output.bytesRead,
        truncated: output.truncated
      });

      return output;
    }
  };
}

function createWriteFileTool(options: WriteFileToolOptions): ToolDefinition<WriteFileToolInput, WriteFileToolOutput> {
  const limits = normalizeWriteFileLimit(options);
  const inputSchema = createWriteFileInputSchema(limits);
  const access = options.access ?? DEFAULT_WRITE_FILE_ACCESS;

  return {
    name: WRITE_FILE_TOOL_NAME,
    description: "Writes a UTF-8 text file under approved filesystem roots with explicit create or overwrite mode.",
    inputSchema,
    outputSchema: writeFileOutputSchema,
    requiredPermissions: ["filesystem.write"],
    async execute(input, context) {
      const mode = input.mode ?? "create";
      const encoding = input.encoding ?? "utf8";
      const bytesWritten = Buffer.byteLength(input.content, "utf8");
      const authorizationRequest: FilesystemAuthorizationRequest = {
        path: input.path,
        policy: context.policy,
        reason: "Write file through filesystem.write_file tool",
        metadata: {
          ...(context.metadata ?? {}),
          operation: "write",
          requestedPath: input.path,
          mode,
          attemptedBytes: bytesWritten
        }
      };

      if (context.audit !== undefined) {
        authorizationRequest.audit = context.audit;
      }

      const authorization = await authorizeFilesystemWrite(options.filesystem, authorizationRequest);

      if (!authorization.ok) {
        await auditWriteFileOperation(context, {
          decision: authorization.error.code === "filesystem.permission_denied" ? "denied" : "not_applicable",
          outcome: authorization.error.code === "filesystem.permission_denied" ? "denied" : "failed",
          requestedPath: input.path,
          mode,
          attemptedBytes: bytesWritten,
          errorCode: authorization.error.code
        });
        throw authorization.error;
      }

      const resolved = authorization.value;
      const parentPath = getPathApiForResolvedPath(resolved.normalizedPath).dirname(resolved.normalizedPath);
      const parentResolution = await options.filesystem.resolvePath(parentPath, "write");
      if (!parentResolution.ok) {
        await auditWriteFileOperation(context, {
          decision: "not_applicable",
          outcome: "failed",
          requestedPath: input.path,
          normalizedPath: resolved.normalizedPath,
          mode,
          attemptedBytes: bytesWritten,
          errorCode: parentResolution.error.code
        });
        throw parentResolution.error;
      }

      const temporaryPath = createTemporarySiblingPath(resolved.normalizedPath);
      const temporaryResolution = await options.filesystem.resolvePath(temporaryPath, "write");
      if (!temporaryResolution.ok) {
        await auditWriteFileOperation(context, {
          decision: "not_applicable",
          outcome: "failed",
          requestedPath: input.path,
          normalizedPath: resolved.normalizedPath,
          mode,
          attemptedBytes: bytesWritten,
          errorCode: temporaryResolution.error.code
        });
        throw temporaryResolution.error;
      }

      try {
        const parentExists = await access.directoryExists(parentResolution.value.normalizedPath);
        if (!parentExists) {
          throw createWriteFileExecutionError("Write file parent directory does not exist", {
            path: resolved.normalizedPath,
            parentPath: parentResolution.value.normalizedPath
          });
        }

        const targetExists = await access.fileExists(resolved.normalizedPath);
        if (mode === "create" && targetExists) {
          throw createWriteFileExecutionError("Write file create mode refused to overwrite an existing file", {
            path: resolved.normalizedPath,
            mode
          });
        }

        if (mode === "overwrite" && !targetExists) {
          throw createWriteFileExecutionError("Write file overwrite mode requires an existing file", {
            path: resolved.normalizedPath,
            mode
          });
        }

        if (mode === "create") {
          await access.createFile(resolved.normalizedPath, input.content, encoding);
        } else {
          await access.overwriteFile(
            resolved.normalizedPath,
            input.content,
            encoding,
            temporaryResolution.value.normalizedPath
          );
        }
      } catch (error) {
        const appError = toAppError(error, {
          code: "tool.execution_failed",
          message: "Write file failed",
          context: {
            path: resolved.normalizedPath,
            mode
          }
        });
        await auditWriteFileOperation(context, {
          decision: "allowed",
          outcome: "failed",
          requestedPath: input.path,
          normalizedPath: resolved.normalizedPath,
          mode,
          attemptedBytes: bytesWritten,
          errorCode: appError.code
        });
        throw appError;
      }

      const output: WriteFileToolOutput = {
        path: input.path,
        normalizedPath: resolved.normalizedPath,
        operation: "write",
        bytesWritten
      };

      await auditWriteFileOperation(context, {
        decision: "allowed",
        outcome: "succeeded",
        requestedPath: input.path,
        normalizedPath: resolved.normalizedPath,
        mode,
        attemptedBytes: bytesWritten,
        bytesWritten: output.bytesWritten
      });

      return output;
    }
  };
}

function createShellExecutionError(message: string, context: JsonObject): AppError {
  return new AppError({
    code: "tool.execution_failed",
    message,
    context
  });
}

function validateShellExecutorResult(result: ShellExecutorResult, maxOutputBytes: number): Result<ShellToolOutput> {
  const schemaResult = shellOutputSchema.validate(result as unknown);
  if (!schemaResult.ok) {
    return schemaResult;
  }

  const stdoutActualBytes = Buffer.byteLength(schemaResult.value.stdout, "utf8");
  const stderrActualBytes = Buffer.byteLength(schemaResult.value.stderr, "utf8");
  if (
    schemaResult.value.stdoutBytes > maxOutputBytes ||
    schemaResult.value.stderrBytes > maxOutputBytes ||
    stdoutActualBytes > maxOutputBytes ||
    stderrActualBytes > maxOutputBytes
  ) {
    return err(
      createShellExecutionError("Shell executor returned output beyond configured limits", {
        maxOutputBytes,
        stdoutBytes: schemaResult.value.stdoutBytes,
        stderrBytes: schemaResult.value.stderrBytes
      })
    );
  }

  return ok(schemaResult.value);
}

function createShellTool(options: ShellToolOptions = {}): ToolDefinition<ShellToolInput, ShellToolOutput> {
  const limits = normalizeShellToolOptions(options);
  const inputSchema = createShellInputSchema(limits);
  const executor = options.executor ?? DEFAULT_SHELL_EXECUTOR;

  return {
    name: SHELL_TOOL_NAME,
    description: "Executes an explicitly approved shell command with bounded cwd, env, timeout, and output.",
    inputSchema,
    outputSchema: shellOutputSchema,
    requiredPermissions: ["shell.execute"],
    async execute(input, context) {
      const cwd = input.cwd ?? limits.defaultCwd;
      const requestedEnv = input.env ?? {};
      const env = createShellProcessEnv(limits.baseEnv, requestedEnv);
      const timeoutMs = input.timeoutMs ?? limits.defaultTimeoutMs;
      const maxOutputBytes = input.maxOutputBytes ?? limits.defaultMaxOutputBytes;
      const shell = input.shell ?? limits.defaultShell;
      const envKeys = Object.keys(requestedEnv).sort();
      const baseEnvKeys = Object.keys(limits.baseEnv).sort();
      const shellRequest: NormalizedShellExecutionRequest = {
        command: input.command,
        cwd,
        env,
        timeoutMs
      };
      const shellPolicy = new ShellPolicy(context.policy);
      const authorization = await shellPolicy.authorize(shellRequest, {
        ...(context.audit !== undefined ? { audit: context.audit } : {}),
        reason: "Execute command through shell.execute tool",
        metadata: {
          ...(context.metadata ?? {}),
          command: input.command,
          cwd,
          envKeys,
          baseEnvKeys,
          timeoutMs,
          maxOutputBytes,
          shell,
          platform: limits.platform
        }
      });

      if (!authorization.ok) {
        await auditShellOperation(context, {
          decision: authorization.error.code === "permission.denied" ? "denied" : "not_applicable",
          outcome: authorization.error.code === "permission.denied" ? "denied" : "failed",
          command: input.command,
          cwd,
          envKeys,
          baseEnvKeys,
          timeoutMs,
          maxOutputBytes,
          shell,
          platform: limits.platform,
          errorCode: authorization.error.code
        });
        throw authorization.error;
      }

      let rawResult: ShellExecutorResult;
      try {
        rawResult = await executor.execute({
          command: input.command,
          cwd,
          env,
          timeoutMs,
          shell,
          platform: limits.platform,
          maxStdoutBytes: maxOutputBytes,
          maxStderrBytes: maxOutputBytes,
          ...(context.signal !== undefined ? { signal: context.signal } : {})
        });
      } catch (error) {
        const appError = toAppError(error, {
          code: "tool.execution_failed",
          message: "Shell executor failed",
          context: {
            command: input.command,
            cwd
          }
        });
        await auditShellOperation(context, {
          decision: "allowed",
          outcome: "failed",
          command: input.command,
          cwd,
          envKeys,
          baseEnvKeys,
          timeoutMs,
          maxOutputBytes,
          shell,
          platform: limits.platform,
          errorCode: appError.code
        });
        throw appError;
      }

      const result = validateShellExecutorResult(rawResult, maxOutputBytes);
      if (!result.ok) {
        await auditShellOperation(context, {
          decision: "allowed",
          outcome: "failed",
          command: input.command,
          cwd,
          envKeys,
          baseEnvKeys,
          timeoutMs,
          maxOutputBytes,
          shell,
          platform: limits.platform,
          status: rawResult.status,
          exitCode: rawResult.exitCode,
          signal: rawResult.signal,
          stdoutBytes: rawResult.stdoutBytes,
          stderrBytes: rawResult.stderrBytes,
          stdoutTruncated: rawResult.stdoutTruncated,
          stderrTruncated: rawResult.stderrTruncated,
          errorCode: result.error.code
        });
        throw result.error;
      }

      const commandFailed = result.value.status === "timed_out" || (result.value.exitCode !== null && result.value.exitCode !== 0);
      await auditShellOperation(context, {
        decision: "allowed",
        outcome: commandFailed ? "failed" : "succeeded",
        command: input.command,
        cwd,
        envKeys,
        baseEnvKeys,
        timeoutMs,
        maxOutputBytes,
        shell,
        platform: limits.platform,
        status: result.value.status,
        exitCode: result.value.exitCode,
        signal: result.value.signal,
        stdoutBytes: result.value.stdoutBytes,
        stderrBytes: result.value.stderrBytes,
        stdoutTruncated: result.value.stdoutTruncated,
        stderrTruncated: result.value.stderrTruncated
      });

      return result.value;
    }
  };
}

function createWebFetchTool(options: WebFetchToolOptions = {}): ToolDefinition<WebFetchToolInput, WebFetchToolOutput> {
  const limits = normalizeWebFetchLimit(options);
  const inputSchema = createWebFetchInputSchema(limits);
  const transport = options.transport ?? DEFAULT_WEB_FETCH_TRANSPORT;

  return {
    name: WEB_FETCH_TOOL_NAME,
    description: "Fetches HTTP(S) text content after explicit network request authorization.",
    inputSchema,
    outputSchema: webFetchOutputSchema,
    requiredPermissions: ["network.request"],
    async execute(input, context) {
      const method = input.method ?? "GET";
      const maxBytes = input.maxBytes ?? limits.defaultMaxBytes;
      const redirect = input.redirect ?? "error";
      const headers = input.headers ?? {};
      const headerNames = Object.keys(headers).sort();
      const sanitizedUrl = sanitizeUrlForAudit(input.url);
      const networkPolicy = new NetworkPolicy(context.policy);
      const authorization = await networkPolicy.authorize(
        {
          url: input.url,
          method,
          headers
        },
        {
          ...(context.audit !== undefined ? { audit: context.audit } : {}),
          reason: "Fetch URL through web.fetch tool",
          metadata: {
            ...(context.metadata ?? {}),
            operation: "fetch",
            requestedUrl: sanitizedUrl,
            method,
            maxBytes,
            redirect,
            headerNames
          }
        }
      );

      if (!authorization.ok) {
        await auditWebFetchOperation(context, {
          decision: authorization.error.code === "permission.denied" ? "denied" : "not_applicable",
          outcome: authorization.error.code === "permission.denied" ? "denied" : "failed",
          requestedUrl: input.url,
          method,
          maxBytes,
          redirect,
          headerNames,
          errorCode: authorization.error.code
        });
        throw authorization.error;
      }

      let response: WebFetchTransportResponse;
      try {
        response = await transport.fetch({
          url: input.url,
          method,
          headers,
          maxBytes: maxBytes + 1,
          redirect
        });
        validateWebFetchTransportResponse(response);
      } catch (error) {
        const appError = toAppError(error, {
          code: "tool.execution_failed",
          message: "Web fetch transport failed",
          context: {
            url: sanitizedUrl,
            method
          }
        });
        await auditWebFetchOperation(context, {
          decision: "allowed",
          outcome: "failed",
          requestedUrl: input.url,
          method,
          maxBytes,
          redirect,
          headerNames,
          errorCode: appError.code
        });
        throw appError;
      }

      const finalUrl = response.finalUrl ?? input.url;
      const sanitizedFinalUrl = sanitizeUrlForAudit(finalUrl);

      if (redirect === "error" && response.status >= 300 && response.status < 400) {
        const error = createWebFetchExecutionError("Web fetch redirect response refused by redirect policy", {
          url: sanitizedUrl,
          status: response.status,
          redirect
        });
        await auditWebFetchOperation(context, {
          decision: "allowed",
          outcome: "failed",
          requestedUrl: input.url,
          method,
          maxBytes,
          redirect,
          status: response.status,
          statusText: response.statusText,
          finalUrl,
          headerNames,
          errorCode: error.code
        });
        throw error;
      }

      const contentType = getHeaderCaseInsensitive(response.headers, "content-type");
      if (!isWebFetchContentTypeAllowed(contentType)) {
        const error = createWebFetchExecutionError("Web fetch refused non-text content type", {
          url: sanitizedUrl,
          contentType: contentType ?? ""
        });
        await auditWebFetchOperation(context, {
          decision: "allowed",
          outcome: "failed",
          requestedUrl: input.url,
          method,
          maxBytes,
          redirect,
          status: response.status,
          statusText: response.statusText,
          finalUrl,
          headerNames,
          errorCode: error.code
        });
        throw error;
      }

      const rawBytes = bodyToBytes(response.body);
      const truncated = rawBytes.length > maxBytes;
      const contentBytes = truncated ? rawBytes.subarray(0, maxBytes) : rawBytes;

      if (isLikelyBinary(contentBytes)) {
        const error = createWebFetchExecutionError("Web fetch refused likely binary content", {
          url: sanitizedUrl
        });
        await auditWebFetchOperation(context, {
          decision: "allowed",
          outcome: "failed",
          requestedUrl: input.url,
          method,
          maxBytes,
          redirect,
          status: response.status,
          statusText: response.statusText,
          bytesRead: contentBytes.length,
          truncated,
          finalUrl,
          headerNames,
          errorCode: error.code
        });
        throw error;
      }

      const output: WebFetchToolOutput = {
        url: sanitizedUrl,
        method,
        redirect,
        status: response.status,
        body: decodeUtf8(contentBytes),
        bytesRead: contentBytes.length,
        truncated
      };

      if (response.statusText !== undefined) {
        output.statusText = response.statusText;
      }

      if (sanitizedFinalUrl !== sanitizedUrl || redirect === "follow") {
        output.finalUrl = sanitizedFinalUrl;
      }

      await auditWebFetchOperation(context, {
        decision: "allowed",
        outcome: "succeeded",
        requestedUrl: input.url,
        method,
        maxBytes,
        redirect,
        status: output.status,
        statusText: output.statusText,
        bytesRead: output.bytesRead,
        truncated: output.truncated,
        finalUrl,
        headerNames
      });

      return output;
    }
  };
}

function createWebSearchTool(options: WebSearchToolOptions): ToolDefinition<WebSearchToolInput, WebSearchToolOutput> {
  const limits = normalizeWebSearchLimit(options);
  const inputSchema = createWebSearchInputSchema(limits);
  const providerNameResult = validateWebSearchProviderName(options.provider.name);

  if (!providerNameResult.ok) {
    throw providerNameResult.error;
  }

  const providerName = providerNameResult.value;

  return {
    name: WEB_SEARCH_TOOL_NAME,
    description: "Runs web search through an injected provider after explicit network request authorization.",
    inputSchema,
    outputSchema: webSearchOutputSchema,
    requiredPermissions: ["network.request"],
    async execute(input, context) {
      const maxResults = input.maxResults ?? limits.defaultMaxResults;
      const queryLength = input.query.length;
      const networkPolicy = new NetworkPolicy(context.policy);
      const authorization = await networkPolicy.authorize(
        {
          resource: `web.search:${providerName}`,
          method: "GET"
        },
        {
          ...(context.audit !== undefined ? { audit: context.audit } : {}),
          reason: "Search web through web.search tool",
          metadata: {
            ...(context.metadata ?? {}),
            operation: "search",
            providerName,
            queryLength,
            maxResults
          }
        }
      );

      if (!authorization.ok) {
        await auditWebSearchOperation(context, {
          decision: authorization.error.code === "permission.denied" ? "denied" : "not_applicable",
          outcome: authorization.error.code === "permission.denied" ? "denied" : "failed",
          providerName,
          queryLength,
          maxResults,
          errorCode: authorization.error.code
        });
        throw authorization.error;
      }

      let response: WebSearchResponse;
      const searchContext: WebSearchProviderSearchContext = {};
      if (context.signal !== undefined) {
        searchContext.signal = context.signal;
      }

      try {
        response = await options.provider.search(
          {
            query: input.query,
            maxResults
          },
          searchContext
        );
      } catch (error) {
        const appError = toAppError(error, {
          code: "tool.execution_failed",
          message: "Web search provider failed",
          context: {
            providerName
          }
        });
        await auditWebSearchOperation(context, {
          decision: "allowed",
          outcome: "failed",
          providerName,
          queryLength,
          maxResults,
          errorCode: appError.code
        });
        throw appError;
      }

      const normalized = normalizeWebSearchProviderResponse(response, providerName, maxResults);
      if (!normalized.ok) {
        await auditWebSearchOperation(context, {
          decision: "allowed",
          outcome: "failed",
          providerName,
          queryLength,
          maxResults,
          errorCode: normalized.error.code
        });
        throw normalized.error;
      }

      const output: WebSearchToolOutput = {
        providerName: normalized.value.providerName,
        queryLength,
        maxResults,
        resultCount: normalized.value.results.length,
        results: normalized.value.results
      };

      await auditWebSearchOperation(context, {
        decision: "allowed",
        outcome: "succeeded",
        providerName: output.providerName,
        queryLength,
        maxResults,
        resultCount: output.resultCount
      });

      return output;
    }
  };
}

function validationFailure(
  direction: "input" | "output",
  tool: ToolDefinition,
  schema: ToolSchema,
  validationError?: AppError
): AppError {
  return new AppError({
    code: direction === "input" ? "tool.invalid_input" : "tool.invalid_output",
    message: `Tool ${direction} validation failed: ${tool.name}`,
    context: {
      toolName: tool.name,
      schemaName: schema.name,
      schemaKind: schema.kind,
      ...(validationError !== undefined ? { validationCode: validationError.code } : {})
    }
  });
}

function validateToolInput<Input extends JsonValue>(
  tool: ToolDefinition<Input, JsonValue>,
  input: unknown
): Result<Input> {
  try {
    const validated = tool.inputSchema.validate(input);
    if (!validated.ok) {
      return err(validationFailure("input", tool, tool.inputSchema, validated.error));
    }

    return validated;
  } catch {
    return err(validationFailure("input", tool, tool.inputSchema));
  }
}

function validateToolOutput<Output extends JsonValue>(
  tool: ToolDefinition<JsonValue, Output>,
  output: unknown
): Result<Output> {
  try {
    const validated = tool.outputSchema.validate(output);
    if (!validated.ok) {
      return err(validationFailure("output", tool, tool.outputSchema, validated.error));
    }

    return validated;
  } catch {
    return err(validationFailure("output", tool, tool.outputSchema));
  }
}

function createInvocationMetadata(tool: ToolDefinition, metadata: Record<string, JsonValue> = {}): JsonObject {
  return {
    ...metadata,
    inputSchema: describeToolSchemaForMetadata(tool.inputSchema),
    outputSchema: describeToolSchemaForMetadata(tool.outputSchema),
    requiredPermissions: [...tool.requiredPermissions]
  };
}

export class ToolRegistry {
  private readonly tools = new Map<ToolName, ToolDefinition<JsonValue, JsonValue>>();

  register<Input extends JsonValue, Output extends JsonValue>(tool: ToolDefinition<Input, Output>): void {
    this.tools.set(tool.name, tool as ToolDefinition<JsonValue, JsonValue>);
  }

  get(name: ToolName): RegisteredTool | undefined {
    const tool = this.tools.get(name);
    if (tool === undefined) {
      return undefined;
    }

    return {
      name: tool.name,
      description: tool.description,
      inputSchema: describeToolSchema(tool.inputSchema),
      outputSchema: describeToolSchema(tool.outputSchema),
      requiredPermissions: [...tool.requiredPermissions]
    };
  }

  async execute<Input, Output>(
    name: ToolName,
    input: Input,
    context: ToolExecutionContext
  ): Promise<Output> {
    const result = await this.executeResult<Output>(name, input, context);

    if (!result.ok) {
      throw result.error;
    }

    return result.value;
  }

  async executeResult<Output = JsonValue>(
    name: ToolName,
    input: unknown,
    context: ToolExecutionContext
  ): Promise<Result<Output>> {
    const result = await this.invokeResult<Output>(
      {
        toolName: name,
        input,
        ...(context.metadata !== undefined ? { metadata: context.metadata } : {})
      },
      context
    );

    if (!result.ok) {
      return result;
    }

    return ok(result.value.output as Output);
  }

  async invoke<Output extends JsonValue = JsonValue>(
    request: ToolInvocationRequest,
    context: ToolExecutionContext
  ): Promise<ToolInvocationResponse<Output>> {
    const result = await this.invokeResult<Output>(request, context);

    if (!result.ok) {
      throw result.error;
    }

    return result.value;
  }

  async invokeResult<Output = JsonValue>(
    request: ToolInvocationRequest,
    context: ToolExecutionContext
  ): Promise<ToolInvocationResult<Extract<Output, JsonValue>>> {
    const tool = this.tools.get(request.toolName);

    if (tool === undefined) {
      await appendAuditEvent(context.audit, {
        sourcePackage: "@dominic-nexus/tools",
        action: "tool.execute",
        decision: "not_applicable",
        resource: {
          type: "tool",
          id: request.toolName,
          name: request.toolName
        },
        outcome: "failed",
        metadata: {
          reason: "Tool not found"
        }
      });

      return err(
        new AppError({
          code: "tool.not_found",
          message: `Tool not found: ${request.toolName}`,
          context: {
            toolName: request.toolName
          }
        })
      );
    }

    const requestMetadata = {
      ...(context.metadata ?? {}),
      ...(request.metadata ?? {})
    };
    const invocationMetadata = createInvocationMetadata(tool, requestMetadata);
    await appendAuditEvent(context.audit, {
      sourcePackage: "@dominic-nexus/tools",
      action: "tool.execute",
      decision: "pending",
      resource: {
        type: "tool",
        id: tool.name,
        name: tool.name
      },
      outcome: "requested",
      metadata: invocationMetadata
    });

    const input = validateToolInput(tool, request.input);
    if (!input.ok) {
      await appendAuditEvent(context.audit, {
        sourcePackage: "@dominic-nexus/tools",
        action: "tool.execute",
        decision: "not_applicable",
        resource: {
          type: "tool",
          id: tool.name,
          name: tool.name
        },
        outcome: "failed",
        metadata: {
          ...invocationMetadata,
          validationPhase: "input",
          errorCode: input.error.code
        }
      });

      return err(input.error);
    }

    const normalizedRequest: NormalizedToolInvocationRequest = {
      toolName: tool.name,
      input: input.value,
      metadata: requestMetadata
    };

    for (const permission of tool.requiredPermissions) {
      const request: PermissionRequest = {
        action: permission,
        reason: `Execute tool: ${tool.name}`,
        resource: tool.name
      };

      if (normalizedRequest.metadata !== undefined) {
        request.metadata = normalizedRequest.metadata;
      }

      let decision: PermissionDecision;

      try {
        decision = await decidePermissionWithAudit(context.policy, request, context.audit);
      } catch (error) {
        await appendAuditEvent(context.audit, {
          sourcePackage: "@dominic-nexus/tools",
          action: "tool.execute",
          decision: "not_applicable",
          resource: {
            type: "tool",
            id: tool.name,
            name: tool.name
          },
          outcome: "failed",
          metadata: {
            permission,
            errorName: error instanceof Error ? error.name : "UnknownError"
          }
        });

        return err(
          toAppError(error, {
            code: "tool.execution_failed",
            message: `Tool permission check failed: ${tool.name}`,
            context: {
              toolName: tool.name
            }
          })
        );
      }

      if (!decision.allowed) {
        await appendAuditEvent(context.audit, {
          sourcePackage: "@dominic-nexus/tools",
          action: "tool.execute",
          decision: "denied",
          resource: {
            type: "tool",
            id: tool.name,
            name: tool.name
          },
          outcome: "denied",
          metadata: {
            permission,
            decisionReason: decision.reason
          }
        });

        return err(
          new AppError({
            code: "tool.permission_denied",
            message: `Tool permission denied: ${tool.name}`,
            context: {
              action: permission,
              toolName: tool.name
            }
          })
        );
      }
    }

    try {
      const output = await tool.execute(normalizedRequest.input, {
        ...context,
        metadata: normalizedRequest.metadata
      });
      const validatedOutput = validateToolOutput(tool, output);
      if (!validatedOutput.ok) {
        await appendAuditEvent(context.audit, {
          sourcePackage: "@dominic-nexus/tools",
          action: "tool.execute",
          decision: "allowed",
          resource: {
            type: "tool",
            id: tool.name,
            name: tool.name
          },
          outcome: "failed",
          metadata: {
            ...invocationMetadata,
            validationPhase: "output",
            errorCode: validatedOutput.error.code
          }
        });

        return err(validatedOutput.error);
      }

      await appendAuditEvent(context.audit, {
        sourcePackage: "@dominic-nexus/tools",
        action: "tool.execute",
        decision: "allowed",
        resource: {
          type: "tool",
          id: tool.name,
          name: tool.name
        },
        outcome: "succeeded",
        metadata: invocationMetadata
      });

      return ok({
        toolName: tool.name,
        output: validatedOutput.value as Extract<Output, JsonValue>,
        metadata: invocationMetadata
      });
    } catch (error) {
      await appendAuditEvent(context.audit, {
        sourcePackage: "@dominic-nexus/tools",
        action: "tool.execute",
        decision: "allowed",
        resource: {
          type: "tool",
          id: tool.name,
          name: tool.name
        },
        outcome: "failed",
        metadata: {
          ...invocationMetadata,
          errorName: error instanceof Error ? error.name : "UnknownError"
        }
      });

      return err(
        toAppError(error, {
          code: "tool.execution_failed",
          message: `Tool execution failed: ${tool.name}`,
          context: {
            toolName: tool.name
          }
        })
      );
    }
  }
}

const echoSchema = jsonValueToolSchema("echo.json");

const echoTool: ToolDefinition<JsonValue, JsonValue> = {
  name: toolName("echo"),
  description: "Returns the provided input.",
  inputSchema: echoSchema,
  outputSchema: echoSchema,
  requiredPermissions: [],
  execute(input) {
    return input;
  }
};

export function registerEchoTool(registry: ToolRegistry): void {
  registry.register(echoTool);
}

export function registerReadFileTool(registry: ToolRegistry, options: ReadFileToolOptions): void {
  registry.register(createReadFileTool(options));
}

export function registerWriteFileTool(registry: ToolRegistry, options: WriteFileToolOptions): void {
  registry.register(createWriteFileTool(options));
}

export function registerWebFetchTool(registry: ToolRegistry, options: WebFetchToolOptions = {}): void {
  registry.register(createWebFetchTool(options));
}

export function registerWebSearchTool(registry: ToolRegistry, options: WebSearchToolOptions): void {
  registry.register(createWebSearchTool(options));
}

export function registerShellTool(registry: ToolRegistry, options: ShellToolOptions = {}): void {
  registry.register(createShellTool(options));
}
