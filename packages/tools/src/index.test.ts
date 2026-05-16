import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { InMemoryAuditSink } from "@dominic-nexus/audit";
import type { PermissionDecision, PermissionRequest, PolicyEngine } from "@dominic-nexus/permissions";
import {
  AppError,
  FixedClock,
  REDACTED_PLACEHOLDER,
  SequentialIdGenerator,
  serializeAppError,
  toolName,
  type JsonValue
} from "@dominic-nexus/shared";
import {
  createToolSchema,
  authorizeFilesystemRead,
  authorizeFilesystemWrite,
  FilesystemRootPolicy,
  jsonValueToolSchema,
  registerEchoTool,
  registerReadFileTool,
  registerShellTool,
  registerWebFetchTool,
  registerWebSearchTool,
  registerWriteFileTool,
  ToolRegistry,
  type FilesystemAccess,
  type ReadFileToolAccess,
  type ShellExecutor,
  type ToolDefinition,
  type WebFetchTransport,
  type WebFetchTransportResponse,
  type WebSearchProvider,
  type WebSearchProviderSearchContext,
  type WebSearchResponse,
  type WriteFileToolAccess
} from "./index.js";
import * as toolsExports from "./index.js";

const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryDirectories.splice(0).map((directory) =>
      rm(directory, {
        force: true,
        recursive: true
      })
    )
  );
});

class RecordingPolicy implements PolicyEngine {
  readonly requests: PermissionRequest[] = [];

  constructor(private readonly decision: PermissionDecision = { allowed: true }) {}

  decide(request: PermissionRequest): PermissionDecision {
    this.requests.push(request);
    return this.decision;
  }
}

class ThrowingPolicy implements PolicyEngine {
  decide(): PermissionDecision {
    throw new Error("policy prompt failed with secret-token");
  }
}

class SequencedPolicy implements PolicyEngine {
  readonly requests: PermissionRequest[] = [];
  private index = 0;

  constructor(private readonly decisions: PermissionDecision[]) {}

  decide(request: PermissionRequest): PermissionDecision {
    this.requests.push(request);
    const decision = this.decisions[this.index] ?? this.decisions.at(-1) ?? { allowed: false };
    this.index += 1;
    return decision;
  }
}

function createAuditContext() {
  const audit = new InMemoryAuditSink();

  return {
    audit,
    context: {
      audit,
      clock: new FixedClock("2026-05-08T00:00:00.000Z"),
      idGenerator: new SequentialIdGenerator({ eventPrefix: "tool-audit" })
    }
  };
}

const missingRealpathAccess: FilesystemAccess = {
  realpath() {
    throw new Error("ENOENT");
  }
};

const jsonSchema = jsonValueToolSchema("test.json");
const stringSchema = createToolSchema<string>({
  name: "test.string",
  kind: "string",
  validate(value) {
    if (typeof value !== "string") {
      return {
        ok: false,
        error: new AppError({
          code: "tool.invalid_input",
          message: "Expected a string"
        })
      };
    }

    return {
      ok: true,
      value
    };
  }
});

function createWindowsFilesystemRootPolicy(): FilesystemRootPolicy {
  return new FilesystemRootPolicy({
    roots: ["C:\\workspace"],
    cwd: "C:\\workspace",
    platform: "win32",
    access: missingRealpathAccess
  });
}

function createRecordingWriteFileAccess(options: {
  directoryExists?: boolean;
  fileExists?: boolean;
} = {}): WriteFileToolAccess {
  return {
    directoryExists: vi.fn(() => options.directoryExists ?? true),
    fileExists: vi.fn(() => options.fileExists ?? false),
    createFile: vi.fn(),
    overwriteFile: vi.fn()
  };
}

function createRecordingWebFetchTransport(
  response: WebFetchTransportResponse = {
    status: 200,
    statusText: "OK",
    headers: {
      "content-type": "text/plain; charset=utf-8"
    },
    body: "hello from web"
  }
): WebFetchTransport & {
  requests: Parameters<WebFetchTransport["fetch"]>[0][];
} {
  const requests: Parameters<WebFetchTransport["fetch"]>[0][] = [];

  return {
    requests,
    fetch: vi.fn((request) => {
      requests.push(request);
      return response;
    })
  };
}

function createRecordingWebSearchProvider(
  response: WebSearchResponse = {
    providerName: "mock-search",
    results: [
      {
        title: "Example result",
        url: "https://example.test/result",
        snippet: "short remote snippet",
        source: "example.test"
      }
    ]
  }
): WebSearchProvider & {
  requests: Parameters<WebSearchProvider["search"]>[0][];
  contexts: WebSearchProviderSearchContext[];
} {
  const requests: Parameters<WebSearchProvider["search"]>[0][] = [];
  const contexts: WebSearchProviderSearchContext[] = [];

  return {
    name: "mock-search",
    requests,
    contexts,
    search: vi.fn((request, searchContext = {}) => {
      requests.push(request);
      contexts.push(searchContext);
      return response;
    })
  };
}

function createRecordingShellExecutor(
  response = {
    status: "completed" as const,
    exitCode: 0,
    signal: null,
    stdout: "shell stdout",
    stderr: "",
    stdoutBytes: Buffer.byteLength("shell stdout"),
    stderrBytes: 0,
    stdoutTruncated: false,
    stderrTruncated: false
  }
): ShellExecutor & {
  requests: Parameters<ShellExecutor["execute"]>[0][];
} {
  const requests: Parameters<ShellExecutor["execute"]>[0][] = [];

  return {
    requests,
    execute: vi.fn((request) => {
      requests.push(request);
      return response;
    })
  };
}

async function createTemporaryDirectory(): Promise<string> {
  const directory = await mkdtemp(path.join(os.tmpdir(), "dominic-nexus-tools-"));
  temporaryDirectories.push(directory);
  return directory;
}

describe("FilesystemRootPolicy", () => {
  it("authorizes relative in-root reads with filesystem.read permission", async () => {
    const filesystem = createWindowsFilesystemRootPolicy();
    const policy = new RecordingPolicy();

    const result = await authorizeFilesystemRead(filesystem, {
      path: "notes\\today.md",
      policy
    });

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value).toEqual({
        operation: "read",
        permission: "filesystem.read",
        requestedPath: "notes\\today.md",
        normalizedPath: "C:\\workspace\\notes\\today.md",
        matchedRoot: "C:\\workspace"
      });
    }
    expect(policy.requests).toEqual([
      expect.objectContaining({
        action: "filesystem.read",
        resource: "C:\\workspace\\notes\\today.md"
      })
    ]);
  });

  it("rejects traversal outside approved roots", async () => {
    const filesystem = createWindowsFilesystemRootPolicy();

    const result = await filesystem.resolvePath("..\\secret.txt", "read");

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(serializeAppError(result.error)).toEqual({
        name: "AppError",
        code: "filesystem.root_violation",
        message: "Filesystem path is outside approved roots",
        context: {
          operation: "read",
          requestedPath: "..\\secret.txt",
          normalizedPath: "C:\\secret.txt"
        }
      });
    }
  });

  it("rejects sibling-prefix escapes", async () => {
    const filesystem = createWindowsFilesystemRootPolicy();

    const result = await filesystem.resolvePath("C:\\workspace-other\\file.txt", "read");

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe("filesystem.root_violation");
    }
  });

  it("treats Windows drive-letter casing as equivalent", async () => {
    const filesystem = new FilesystemRootPolicy({
      roots: ["C:\\Workspace"],
      cwd: "C:\\Workspace",
      platform: "win32",
      access: missingRealpathAccess
    });

    const result = await filesystem.resolvePath("c:\\workspace\\notes.txt", "read");

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value.normalizedPath).toBe("c:\\workspace\\notes.txt");
      expect(result.value.matchedRoot).toBe("C:\\Workspace");
    }
  });

  it("rejects Windows paths on unapproved drives", async () => {
    const filesystem = createWindowsFilesystemRootPolicy();

    const result = await filesystem.resolvePath("D:\\workspace\\notes.txt", "read");

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe("filesystem.root_violation");
    }
  });

  it("handles mixed Windows path separators", async () => {
    const filesystem = createWindowsFilesystemRootPolicy();

    const result = await filesystem.resolvePath("C:/workspace\\notes/today.md", "read");

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value.normalizedPath).toBe("C:\\workspace\\notes\\today.md");
    }
  });

  it("rejects Windows drive-relative paths", async () => {
    const filesystem = createWindowsFilesystemRootPolicy();

    const result = await filesystem.resolvePath("C:secret.txt", "read");

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(serializeAppError(result.error)).toEqual({
        name: "AppError",
        code: "filesystem.root_violation",
        message: "Windows drive-relative paths are not allowed",
        context: {
          field: "path"
        }
      });
    }
  });

  it("rejects symlink escapes when realpath resolves outside approved roots", async () => {
    const filesystem = new FilesystemRootPolicy({
      roots: ["C:\\workspace"],
      cwd: "C:\\workspace",
      platform: "win32",
      access: {
        realpath(filePath) {
          expect(filePath).toBe("C:\\workspace\\link\\secret.txt");
          return "C:\\outside\\secret.txt";
        }
      }
    });

    const result = await filesystem.resolvePath("link\\secret.txt", "read");

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(serializeAppError(result.error)).toEqual({
        name: "AppError",
        code: "filesystem.root_violation",
        message: "Filesystem real path is outside approved roots",
        context: {
          operation: "read",
          requestedPath: "link\\secret.txt",
          normalizedPath: "C:\\workspace\\link\\secret.txt",
          realPath: "C:\\outside\\secret.txt"
        }
      });
    }
  });

  it("denies writes when filesystem.write permission is denied", async () => {
    const filesystem = createWindowsFilesystemRootPolicy();
    const policy = new RecordingPolicy({ allowed: false, reason: "blocked" });

    const result = await authorizeFilesystemWrite(filesystem, {
      path: "notes\\today.md",
      policy
    });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(serializeAppError(result.error)).toEqual({
        name: "AppError",
        code: "filesystem.permission_denied",
        message: "Filesystem write permission denied",
        context: {
          action: "filesystem.write",
          operation: "write",
          path: "C:\\workspace\\notes\\today.md"
        }
      });
    }
    expect(policy.requests).toEqual([
      expect.objectContaining({
        action: "filesystem.write",
        resource: "C:\\workspace\\notes\\today.md"
      })
    ]);
  });

  it("authorizes writes only after filesystem.write permission is allowed", async () => {
    const filesystem = createWindowsFilesystemRootPolicy();
    const policy = new RecordingPolicy();

    const result = await authorizeFilesystemWrite(filesystem, {
      path: "notes\\today.md",
      policy
    });

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value).toMatchObject({
        operation: "write",
        permission: "filesystem.write",
        normalizedPath: "C:\\workspace\\notes\\today.md",
        matchedRoot: "C:\\workspace"
      });
    }
    expect(policy.requests[0]?.action).toBe("filesystem.write");
  });
});

describe("ToolRegistry", () => {
  it("registers the built-in echo tool without exporting its handler", async () => {
    const policy = new RecordingPolicy();
    const registry = new ToolRegistry();

    registerEchoTool(registry);

    await expect(registry.execute(toolName("echo"), "hello", { policy })).resolves.toBe("hello");
    expect(registry.get(toolName("echo"))).not.toHaveProperty("execute");
    expect(toolsExports).not.toHaveProperty("echoTool");
  });

  it("reads an in-root UTF-8 file through invokeResult", async () => {
    const root = await createTemporaryDirectory();
    await mkdir(path.join(root, "notes"));
    await writeFile(path.join(root, "notes", "today.md"), "hello from disk", "utf8");
    const policy = new RecordingPolicy();
    const registry = new ToolRegistry();
    const filesystem = new FilesystemRootPolicy({
      roots: [root],
      cwd: root
    });

    registerReadFileTool(registry, {
      filesystem
    });

    const result = await registry.invokeResult<{
      path: string;
      normalizedPath: string;
      content: string;
      bytesRead: number;
      truncated: boolean;
    }>(
      {
        toolName: toolName("filesystem.read_file"),
        input: {
          path: path.join("notes", "today.md")
        }
      },
      { policy }
    );

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value.output).toEqual({
        path: path.join("notes", "today.md"),
        normalizedPath: path.join(root, "notes", "today.md"),
        content: "hello from disk",
        bytesRead: Buffer.byteLength("hello from disk"),
        truncated: false
      });
    }
    expect(policy.requests.map((request) => request.action)).toEqual(["filesystem.read", "filesystem.read"]);
    expect(policy.requests[1]).toEqual(
      expect.objectContaining({
        action: "filesystem.read",
        resource: path.join(root, "notes", "today.md")
      })
    );
  });

  it("rejects read paths outside the configured root before file access", async () => {
    const policy = new RecordingPolicy();
    const registry = new ToolRegistry();
    const filesystem = createWindowsFilesystemRootPolicy();
    const access: ReadFileToolAccess = {
      readBytes: vi.fn()
    };

    registerReadFileTool(registry, {
      filesystem,
      access
    });

    const result = await registry.invokeResult(
      {
        toolName: toolName("filesystem.read_file"),
        input: {
          path: "..\\secret.txt"
        }
      },
      { policy }
    );

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe("filesystem.root_violation");
    }
    expect(access.readBytes).not.toHaveBeenCalled();
  });

  it("does not reach file access when filesystem.read permission is denied", async () => {
    const policy = new RecordingPolicy({ allowed: false, reason: "blocked" });
    const registry = new ToolRegistry();
    const filesystem = createWindowsFilesystemRootPolicy();
    const access: ReadFileToolAccess = {
      readBytes: vi.fn()
    };

    registerReadFileTool(registry, {
      filesystem,
      access
    });

    const result = await registry.invokeResult(
      {
        toolName: toolName("filesystem.read_file"),
        input: {
          path: "notes\\today.md"
        }
      },
      { policy }
    );

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(serializeAppError(result.error)).toEqual({
        name: "AppError",
        code: "tool.permission_denied",
        message: "Tool permission denied: filesystem.read_file",
        context: {
          action: "filesystem.read",
          toolName: "filesystem.read_file"
        }
      });
    }
    expect(access.readBytes).not.toHaveBeenCalled();
    expect(policy.requests).toHaveLength(1);
  });

  it("rejects invalid read input before permissions or file access", async () => {
    const policy = new RecordingPolicy();
    const registry = new ToolRegistry();
    const filesystem = createWindowsFilesystemRootPolicy();
    const access: ReadFileToolAccess = {
      readBytes: vi.fn()
    };

    registerReadFileTool(registry, {
      filesystem,
      access
    });

    const result = await registry.invokeResult(
      {
        toolName: toolName("filesystem.read_file"),
        input: {
          path: "notes\\today.md",
          unexpected: true
        }
      },
      { policy }
    );

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe("tool.invalid_input");
    }
    expect(policy.requests).toHaveLength(0);
    expect(access.readBytes).not.toHaveBeenCalled();
  });

  it("truncates large files at the requested maxBytes limit", async () => {
    const policy = new RecordingPolicy();
    const registry = new ToolRegistry();
    const filesystem = createWindowsFilesystemRootPolicy();
    const access: ReadFileToolAccess = {
      readBytes: vi.fn(() => Buffer.from("abcdef", "utf8"))
    };

    registerReadFileTool(registry, {
      filesystem,
      access,
      defaultMaxBytes: 4,
      absoluteMaxBytes: 10
    });

    const result = await registry.invokeResult<{
      content: string;
      bytesRead: number;
      truncated: boolean;
    }>(
      {
        toolName: toolName("filesystem.read_file"),
        input: {
          path: "notes\\today.md",
          maxBytes: 5
        }
      },
      { policy }
    );

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value.output).toMatchObject({
        content: "abcde",
        bytesRead: 5,
        truncated: true
      });
    }
    expect(access.readBytes).toHaveBeenCalledWith("C:\\workspace\\notes\\today.md", 6);
  });

  it("refuses likely binary file content", async () => {
    const policy = new RecordingPolicy();
    const registry = new ToolRegistry();
    const filesystem = createWindowsFilesystemRootPolicy();
    const access: ReadFileToolAccess = {
      readBytes: vi.fn(() => Buffer.from([65, 0, 66]))
    };

    registerReadFileTool(registry, {
      filesystem,
      access
    });

    const result = await registry.invokeResult(
      {
        toolName: toolName("filesystem.read_file"),
        input: {
          path: "notes\\binary.dat"
        }
      },
      { policy }
    );

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(serializeAppError(result.error)).toEqual({
        name: "AppError",
        code: "tool.execution_failed",
        message: "Read file refused likely binary content",
        context: {
          path: "C:\\workspace\\notes\\binary.dat"
        }
      });
    }
    expect(access.readBytes).toHaveBeenCalledOnce();
  });

  it("audits read file metadata without file content", async () => {
    const { audit, context } = createAuditContext();
    const policy = new RecordingPolicy();
    const registry = new ToolRegistry();
    const filesystem = createWindowsFilesystemRootPolicy();
    const access: ReadFileToolAccess = {
      readBytes: vi.fn(() => Buffer.from("TOP-SECRET-CONTENT", "utf8"))
    };

    registerReadFileTool(registry, {
      filesystem,
      access
    });

    const result = await registry.invokeResult(
      {
        toolName: toolName("filesystem.read_file"),
        input: {
          path: "notes\\today.md"
        }
      },
      { policy, audit: context }
    );

    expect(result.ok).toBe(true);
    expect(audit.listEvents()).toContainEqual(
      expect.objectContaining({
        action: "filesystem.read",
        decision: "allowed",
        outcome: "succeeded",
        metadata: expect.objectContaining({
          operation: "read",
          normalizedPath: "C:\\workspace\\notes\\today.md",
          bytesRead: Buffer.byteLength("TOP-SECRET-CONTENT"),
          truncated: false
        })
      })
    );
    expect(JSON.stringify(audit.listEvents())).not.toContain("TOP-SECRET-CONTENT");
  });

  it("creates an in-root UTF-8 file through invokeResult", async () => {
    const root = await createTemporaryDirectory();
    await mkdir(path.join(root, "notes"));
    const policy = new RecordingPolicy();
    const registry = new ToolRegistry();
    const filesystem = new FilesystemRootPolicy({
      roots: [root],
      cwd: root
    });

    registerWriteFileTool(registry, {
      filesystem
    });

    const result = await registry.invokeResult<{
      path: string;
      normalizedPath: string;
      operation: "write";
      bytesWritten: number;
    }>(
      {
        toolName: toolName("filesystem.write_file"),
        input: {
          path: path.join("notes", "created.md"),
          content: "created content"
        }
      },
      { policy }
    );

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value.output).toEqual({
        path: path.join("notes", "created.md"),
        normalizedPath: path.join(root, "notes", "created.md"),
        operation: "write",
        bytesWritten: Buffer.byteLength("created content")
      });
    }
    await expect(readFile(path.join(root, "notes", "created.md"), "utf8")).resolves.toBe("created content");
    expect(policy.requests.map((request) => request.action)).toEqual(["filesystem.write", "filesystem.write"]);
  });

  it("overwrites an in-root file only with explicit overwrite mode", async () => {
    const root = await createTemporaryDirectory();
    await mkdir(path.join(root, "notes"));
    const targetPath = path.join(root, "notes", "today.md");
    await writeFile(targetPath, "original", "utf8");
    const registry = new ToolRegistry();
    const filesystem = new FilesystemRootPolicy({
      roots: [root],
      cwd: root
    });

    registerWriteFileTool(registry, {
      filesystem
    });

    const defaultCreateResult = await registry.invokeResult(
      {
        toolName: toolName("filesystem.write_file"),
        input: {
          path: path.join("notes", "today.md"),
          content: "should not replace"
        }
      },
      { policy: new RecordingPolicy() }
    );

    expect(defaultCreateResult.ok).toBe(false);
    await expect(readFile(targetPath, "utf8")).resolves.toBe("original");

    const overwriteResult = await registry.invokeResult<{
      bytesWritten: number;
      operation: "write";
    }>(
      {
        toolName: toolName("filesystem.write_file"),
        input: {
          path: path.join("notes", "today.md"),
          content: "replacement",
          mode: "overwrite"
        }
      },
      { policy: new RecordingPolicy() }
    );

    expect(overwriteResult.ok).toBe(true);
    if (overwriteResult.ok) {
      expect(overwriteResult.value.output).toMatchObject({
        operation: "write",
        bytesWritten: Buffer.byteLength("replacement")
      });
    }
    await expect(readFile(targetPath, "utf8")).resolves.toBe("replacement");
  });

  it("rejects write paths outside the configured root before write access", async () => {
    const policy = new RecordingPolicy();
    const registry = new ToolRegistry();
    const filesystem = createWindowsFilesystemRootPolicy();
    const access = createRecordingWriteFileAccess();

    registerWriteFileTool(registry, {
      filesystem,
      access
    });

    const result = await registry.invokeResult(
      {
        toolName: toolName("filesystem.write_file"),
        input: {
          path: "..\\secret.txt",
          content: "no write"
        }
      },
      { policy }
    );

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe("filesystem.root_violation");
    }
    expect(access.directoryExists).not.toHaveBeenCalled();
    expect(access.fileExists).not.toHaveBeenCalled();
    expect(access.createFile).not.toHaveBeenCalled();
    expect(access.overwriteFile).not.toHaveBeenCalled();
  });

  it("does not reach write access when filesystem.write permission is denied", async () => {
    const policy = new RecordingPolicy({ allowed: false, reason: "blocked" });
    const registry = new ToolRegistry();
    const filesystem = createWindowsFilesystemRootPolicy();
    const access = createRecordingWriteFileAccess();

    registerWriteFileTool(registry, {
      filesystem,
      access
    });

    const result = await registry.invokeResult(
      {
        toolName: toolName("filesystem.write_file"),
        input: {
          path: "notes\\today.md",
          content: "blocked"
        }
      },
      { policy }
    );

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(serializeAppError(result.error)).toEqual({
        name: "AppError",
        code: "tool.permission_denied",
        message: "Tool permission denied: filesystem.write_file",
        context: {
          action: "filesystem.write",
          toolName: "filesystem.write_file"
        }
      });
    }
    expect(policy.requests).toHaveLength(1);
    expect(access.createFile).not.toHaveBeenCalled();
    expect(access.overwriteFile).not.toHaveBeenCalled();
  });

  it("does not reach write access when path authorization permission is denied", async () => {
    const policy = new SequencedPolicy([{ allowed: true }, { allowed: false, reason: "path blocked" }]);
    const registry = new ToolRegistry();
    const filesystem = createWindowsFilesystemRootPolicy();
    const access = createRecordingWriteFileAccess();

    registerWriteFileTool(registry, {
      filesystem,
      access
    });

    const result = await registry.invokeResult(
      {
        toolName: toolName("filesystem.write_file"),
        input: {
          path: "notes\\today.md",
          content: "blocked"
        }
      },
      { policy }
    );

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe("filesystem.permission_denied");
    }
    expect(policy.requests.map((request) => request.action)).toEqual(["filesystem.write", "filesystem.write"]);
    expect(access.createFile).not.toHaveBeenCalled();
    expect(access.overwriteFile).not.toHaveBeenCalled();
  });

  it("rejects invalid write input before permissions or write access", async () => {
    const policy = new RecordingPolicy();
    const registry = new ToolRegistry();
    const filesystem = createWindowsFilesystemRootPolicy();
    const access = createRecordingWriteFileAccess();

    registerWriteFileTool(registry, {
      filesystem,
      access
    });

    const result = await registry.invokeResult(
      {
        toolName: toolName("filesystem.write_file"),
        input: {
          path: "notes\\today.md",
          content: "hello",
          unexpected: true
        }
      },
      { policy }
    );

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe("tool.invalid_input");
    }
    expect(policy.requests).toHaveLength(0);
    expect(access.createFile).not.toHaveBeenCalled();
    expect(access.overwriteFile).not.toHaveBeenCalled();
  });

  it("fails create mode for an existing file without mutating it", async () => {
    const root = await createTemporaryDirectory();
    const targetPath = path.join(root, "existing.md");
    await writeFile(targetPath, "original", "utf8");
    const registry = new ToolRegistry();

    registerWriteFileTool(registry, {
      filesystem: new FilesystemRootPolicy({
        roots: [root],
        cwd: root
      })
    });

    const result = await registry.invokeResult(
      {
        toolName: toolName("filesystem.write_file"),
        input: {
          path: "existing.md",
          content: "new content",
          mode: "create"
        }
      },
      { policy: new RecordingPolicy() }
    );

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe("tool.execution_failed");
    }
    await expect(readFile(targetPath, "utf8")).resolves.toBe("original");
  });

  it("fails overwrite mode for a missing file without creating it", async () => {
    const root = await createTemporaryDirectory();
    const targetPath = path.join(root, "missing.md");
    const registry = new ToolRegistry();

    registerWriteFileTool(registry, {
      filesystem: new FilesystemRootPolicy({
        roots: [root],
        cwd: root
      })
    });

    const result = await registry.invokeResult(
      {
        toolName: toolName("filesystem.write_file"),
        input: {
          path: "missing.md",
          content: "new content",
          mode: "overwrite"
        }
      },
      { policy: new RecordingPolicy() }
    );

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe("tool.execution_failed");
    }
    await expect(readFile(targetPath, "utf8")).rejects.toMatchObject({
      code: "ENOENT"
    });
  });

  it("rejects parent symlink escapes before write access for new files", async () => {
    const filesystem = new FilesystemRootPolicy({
      roots: ["C:\\workspace"],
      cwd: "C:\\workspace",
      platform: "win32",
      access: {
        realpath(filePath) {
          if (filePath === "C:\\workspace\\link") {
            return "C:\\outside";
          }

          throw new Error("ENOENT");
        }
      }
    });
    const policy = new RecordingPolicy();
    const registry = new ToolRegistry();
    const access = createRecordingWriteFileAccess();

    registerWriteFileTool(registry, {
      filesystem,
      access
    });

    const result = await registry.invokeResult(
      {
        toolName: toolName("filesystem.write_file"),
        input: {
          path: "link\\created.md",
          content: "no write"
        }
      },
      { policy }
    );

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe("filesystem.root_violation");
    }
    expect(access.directoryExists).not.toHaveBeenCalled();
    expect(access.createFile).not.toHaveBeenCalled();
    expect(access.overwriteFile).not.toHaveBeenCalled();
  });

  it("rejects large write content before permissions or write access", async () => {
    const policy = new RecordingPolicy();
    const registry = new ToolRegistry();
    const access = createRecordingWriteFileAccess();

    registerWriteFileTool(registry, {
      filesystem: createWindowsFilesystemRootPolicy(),
      access,
      absoluteMaxBytes: 4
    });

    const result = await registry.invokeResult(
      {
        toolName: toolName("filesystem.write_file"),
        input: {
          path: "notes\\large.md",
          content: "12345"
        }
      },
      { policy }
    );

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe("tool.invalid_input");
    }
    expect(policy.requests).toHaveLength(0);
    expect(access.createFile).not.toHaveBeenCalled();
    expect(access.overwriteFile).not.toHaveBeenCalled();
  });

  it("audits write file metadata without file content", async () => {
    const { audit, context } = createAuditContext();
    const policy = new RecordingPolicy();
    const registry = new ToolRegistry();
    const filesystem = createWindowsFilesystemRootPolicy();
    const access = createRecordingWriteFileAccess();

    registerWriteFileTool(registry, {
      filesystem,
      access
    });

    const result = await registry.invokeResult(
      {
        toolName: toolName("filesystem.write_file"),
        input: {
          path: "notes\\today.md",
          content: "TOP-SECRET-CONTENT"
        }
      },
      { policy, audit: context }
    );

    expect(result.ok).toBe(true);
    expect(audit.listEvents()).toContainEqual(
      expect.objectContaining({
        action: "filesystem.write",
        decision: "allowed",
        outcome: "succeeded",
        metadata: expect.objectContaining({
          operation: "write",
          requestedPath: "notes\\today.md",
          normalizedPath: "C:\\workspace\\notes\\today.md",
          mode: "create",
          attemptedBytes: Buffer.byteLength("TOP-SECRET-CONTENT"),
          bytesWritten: Buffer.byteLength("TOP-SECRET-CONTENT")
        })
      })
    );
    expect(JSON.stringify(audit.listEvents())).not.toContain("TOP-SECRET-CONTENT");
  });

  it("fetches text content through invokeResult using an injected transport", async () => {
    const policy = new RecordingPolicy();
    const registry = new ToolRegistry();
    const transport = createRecordingWebFetchTransport();

    registerWebFetchTool(registry, {
      transport
    });

    const result = await registry.invokeResult<{
      url: string;
      status: number;
      statusText?: string;
      body: string;
      bytesRead: number;
      truncated: boolean;
      method: "GET";
      redirect: "error";
    }>(
      {
        toolName: toolName("web.fetch"),
        input: {
          url: "https://example.test/path?token=secret#frag",
          maxBytes: 64
        }
      },
      { policy }
    );

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value.output).toEqual({
        url: "https://example.test/path",
        status: 200,
        statusText: "OK",
        body: "hello from web",
        bytesRead: Buffer.byteLength("hello from web"),
        truncated: false,
        method: "GET",
        redirect: "error"
      });
    }
    expect(transport.fetch).toHaveBeenCalledWith({
      url: "https://example.test/path?token=secret#frag",
      method: "GET",
      headers: {},
      maxBytes: 65,
      redirect: "error"
    });
    expect(policy.requests.map((request) => request.action)).toEqual(["network.request", "network.request"]);
    expect(policy.requests[1]).toEqual(
      expect.objectContaining({
        action: "network.request",
        resource: "https://example.test/path"
      })
    );
  });

  it("does not reach web transport when default policy denies registry-level network permission", async () => {
    const policy = new RecordingPolicy({ allowed: false, reason: "blocked" });
    const registry = new ToolRegistry();
    const transport = createRecordingWebFetchTransport();

    registerWebFetchTool(registry, {
      transport
    });

    const result = await registry.invokeResult(
      {
        toolName: toolName("web.fetch"),
        input: {
          url: "https://example.test/"
        }
      },
      { policy }
    );

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(serializeAppError(result.error)).toEqual({
        name: "AppError",
        code: "tool.permission_denied",
        message: "Tool permission denied: web.fetch",
        context: {
          action: "network.request",
          toolName: "web.fetch"
        }
      });
    }
    expect(policy.requests).toHaveLength(1);
    expect(transport.fetch).not.toHaveBeenCalled();
  });

  it("does not reach web transport when handler-level network authorization denies the exact request", async () => {
    const policy = new SequencedPolicy([{ allowed: true }, { allowed: false, reason: "blocked host" }]);
    const registry = new ToolRegistry();
    const transport = createRecordingWebFetchTransport();

    registerWebFetchTool(registry, {
      transport
    });

    const result = await registry.invokeResult(
      {
        toolName: toolName("web.fetch"),
        input: {
          url: "https://blocked.example/path"
        }
      },
      { policy }
    );

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(serializeAppError(result.error)).toEqual({
        name: "AppError",
        code: "permission.denied",
        message: "Network request permission denied",
        context: {
          action: "network.request",
          resource: "https://blocked.example/path"
        }
      });
    }
    expect(policy.requests.map((request) => request.action)).toEqual(["network.request", "network.request"]);
    expect(policy.requests[1]).toEqual(
      expect.objectContaining({
        action: "network.request",
        resource: "https://blocked.example/path"
      })
    );
    expect(transport.fetch).not.toHaveBeenCalled();
  });

  it("rejects invalid web fetch input before permissions or transport", async () => {
    const policy = new RecordingPolicy();
    const registry = new ToolRegistry();
    const transport = createRecordingWebFetchTransport();

    registerWebFetchTool(registry, {
      transport
    });

    const result = await registry.invokeResult(
      {
        toolName: toolName("web.fetch"),
        input: {
          url: "https://example.test/",
          unexpected: true
        }
      },
      { policy }
    );

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe("tool.invalid_input");
    }
    expect(policy.requests).toHaveLength(0);
    expect(transport.fetch).not.toHaveBeenCalled();
  });

  it("rejects malformed urls and unsupported protocols before permissions or transport", async () => {
    const policy = new RecordingPolicy();
    const registry = new ToolRegistry();
    const transport = createRecordingWebFetchTransport();

    registerWebFetchTool(registry, {
      transport
    });

    for (const url of ["not a url", "ftp://example.test/file", "https://user:pass@example.test/secret"]) {
      const result = await registry.invokeResult(
        {
          toolName: toolName("web.fetch"),
          input: {
            url
          }
        },
        { policy }
      );

      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.error.code).toBe("tool.invalid_input");
      }
    }

    expect(policy.requests).toHaveLength(0);
    expect(transport.fetch).not.toHaveBeenCalled();
  });

  it("rejects NUL-byte urls before permissions or transport", async () => {
    const policy = new RecordingPolicy();
    const registry = new ToolRegistry();
    const transport = createRecordingWebFetchTransport();

    registerWebFetchTool(registry, {
      transport
    });

    const result = await registry.invokeResult(
      {
        toolName: toolName("web.fetch"),
        input: {
          url: "https://example.test/\0secret"
        }
      },
      { policy }
    );

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe("tool.invalid_input");
    }
    expect(policy.requests).toHaveLength(0);
    expect(transport.fetch).not.toHaveBeenCalled();
  });

  it("rejects too many web fetch request headers before permissions or transport", async () => {
    const policy = new RecordingPolicy();
    const registry = new ToolRegistry();
    const transport = createRecordingWebFetchTransport();
    const headers = Object.fromEntries(Array.from({ length: 21 }, (_, index) => [`X-Test-${index}`, "value"]));

    registerWebFetchTool(registry, {
      transport
    });

    const result = await registry.invokeResult(
      {
        toolName: toolName("web.fetch"),
        input: {
          url: "https://example.test/",
          headers
        }
      },
      { policy }
    );

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe("tool.invalid_input");
    }
    expect(policy.requests).toHaveLength(0);
    expect(transport.fetch).not.toHaveBeenCalled();
  });

  it("rejects oversized web fetch request header names and values before permissions or transport", async () => {
    const policy = new RecordingPolicy();
    const registry = new ToolRegistry();
    const transport = createRecordingWebFetchTransport();

    registerWebFetchTool(registry, {
      transport
    });

    for (const headers of [
      {
        [`X-${"A".repeat(127)}`]: "value"
      },
      {
        "X-Test": "A".repeat(4097)
      }
    ]) {
      const result = await registry.invokeResult(
        {
          toolName: toolName("web.fetch"),
          input: {
            url: "https://example.test/",
            headers
          }
        },
        { policy }
      );

      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.error.code).toBe("tool.invalid_input");
      }
    }

    expect(policy.requests).toHaveLength(0);
    expect(transport.fetch).not.toHaveBeenCalled();
  });

  it("makes redirect behavior explicit and rejects redirects when policy is error", async () => {
    const policy = new RecordingPolicy();
    const registry = new ToolRegistry();
    const transport = createRecordingWebFetchTransport({
      status: 302,
      statusText: "Found",
      headers: {
        "content-type": "text/plain",
        location: "https://example.test/next"
      },
      body: "redirect"
    });

    registerWebFetchTool(registry, {
      transport
    });

    const result = await registry.invokeResult(
      {
        toolName: toolName("web.fetch"),
        input: {
          url: "https://example.test/start",
          redirect: "error"
        }
      },
      { policy }
    );

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe("tool.execution_failed");
    }
    expect(transport.fetch).toHaveBeenCalledWith(
      expect.objectContaining({
        redirect: "error"
      })
    );
  });

  it("passes explicit follow redirect policy and sanitizes finalUrl", async () => {
    const policy = new RecordingPolicy();
    const registry = new ToolRegistry();
    const transport = createRecordingWebFetchTransport({
      status: 200,
      statusText: "OK",
      headers: {
        "content-type": "text/plain"
      },
      body: "followed",
      finalUrl: "https://example.test/final?session=secret#hash"
    });

    registerWebFetchTool(registry, {
      transport
    });

    const result = await registry.invokeResult<{
      finalUrl: string;
      redirect: "follow";
    }>(
      {
        toolName: toolName("web.fetch"),
        input: {
          url: "https://example.test/start",
          redirect: "follow"
        }
      },
      { policy }
    );

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value.output).toMatchObject({
        redirect: "follow",
        finalUrl: "https://example.test/final"
      });
    }
    expect(transport.fetch).toHaveBeenCalledWith(
      expect.objectContaining({
        redirect: "follow"
      })
    );
  });

  it("truncates web fetch responses at the requested maxBytes limit", async () => {
    const policy = new RecordingPolicy();
    const registry = new ToolRegistry();
    const transport = createRecordingWebFetchTransport({
      status: 200,
      headers: {
        "content-type": "text/plain"
      },
      body: "abcdef"
    });

    registerWebFetchTool(registry, {
      transport,
      defaultMaxBytes: 4,
      absoluteMaxBytes: 10
    });

    const result = await registry.invokeResult<{
      body: string;
      bytesRead: number;
      truncated: boolean;
    }>(
      {
        toolName: toolName("web.fetch"),
        input: {
          url: "https://example.test/data",
          maxBytes: 5
        }
      },
      { policy }
    );

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value.output).toMatchObject({
        body: "abcde",
        bytesRead: 5,
        truncated: true
      });
    }
    expect(transport.fetch).toHaveBeenCalledWith(
      expect.objectContaining({
        maxBytes: 6
      })
    );
  });

  it("rejects non-text web fetch response content types", async () => {
    const policy = new RecordingPolicy();
    const registry = new ToolRegistry();
    const transport = createRecordingWebFetchTransport({
      status: 200,
      headers: {
        "content-type": "application/octet-stream"
      },
      body: "not text"
    });

    registerWebFetchTool(registry, {
      transport
    });

    const result = await registry.invokeResult(
      {
        toolName: toolName("web.fetch"),
        input: {
          url: "https://example.test/blob"
        }
      },
      { policy }
    );

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(serializeAppError(result.error)).toEqual({
        name: "AppError",
        code: "tool.execution_failed",
        message: "Web fetch refused non-text content type",
        context: {
          url: "https://example.test/blob",
          contentType: "application/octet-stream"
        }
      });
    }
    expect(transport.fetch).toHaveBeenCalledOnce();
  });

  it("rejects likely binary web fetch response content", async () => {
    const policy = new RecordingPolicy();
    const registry = new ToolRegistry();
    const transport = createRecordingWebFetchTransport({
      status: 200,
      headers: {
        "content-type": "text/plain"
      },
      body: Buffer.from([65, 0, 66])
    });

    registerWebFetchTool(registry, {
      transport
    });

    const result = await registry.invokeResult(
      {
        toolName: toolName("web.fetch"),
        input: {
          url: "https://example.test/binary"
        }
      },
      { policy }
    );

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(serializeAppError(result.error)).toEqual({
        name: "AppError",
        code: "tool.execution_failed",
        message: "Web fetch refused likely binary content",
        context: {
          url: "https://example.test/binary"
        }
      });
    }
    expect(transport.fetch).toHaveBeenCalledOnce();
  });

  it("audits web fetch metadata without sensitive headers or response body", async () => {
    const { audit, context } = createAuditContext();
    const policy = new RecordingPolicy();
    const registry = new ToolRegistry();
    const transport = createRecordingWebFetchTransport({
      status: 200,
      statusText: "OK",
      headers: {
        "content-type": "text/plain"
      },
      body: "TOP-SECRET-CONTENT"
    });

    registerWebFetchTool(registry, {
      transport
    });

    const result = await registry.invokeResult(
      {
        toolName: toolName("web.fetch"),
        input: {
          url: "https://example.test/path?token=query-secret#hash",
          headers: {
            Authorization: "Bearer raw-secret-token",
            Cookie: "sid=raw-cookie",
            "X-Trace": "trace-value"
          }
        }
      },
      { policy, audit: context }
    );

    expect(result.ok).toBe(true);
    expect(audit.listEvents()).toContainEqual(
      expect.objectContaining({
        action: "web.fetch",
        decision: "allowed",
        outcome: "succeeded",
        metadata: expect.objectContaining({
          operation: "fetch",
          requestedUrl: "https://example.test/path",
          method: "GET",
          status: 200,
          bytesRead: Buffer.byteLength("TOP-SECRET-CONTENT"),
          truncated: false,
          headerNames: ["Authorization", "Cookie", "X-Trace"]
        })
      })
    );
    expect(JSON.stringify(audit.listEvents())).not.toContain("TOP-SECRET-CONTENT");
    expect(JSON.stringify(audit.listEvents())).not.toContain("raw-secret-token");
    expect(JSON.stringify(audit.listEvents())).not.toContain("raw-cookie");
    expect(JSON.stringify(audit.listEvents())).not.toContain("query-secret");
  });

  it("searches through invokeResult using an injected web search provider", async () => {
    const policy = new RecordingPolicy();
    const registry = new ToolRegistry();
    const provider = createRecordingWebSearchProvider({
      providerName: "mock-search",
      results: [
        {
          title: "Dominic Nexus",
          url: "https://example.test/nexus?tracking=allowed",
          snippet: "project notes",
          source: "example.test"
        }
      ]
    });

    registerWebSearchTool(registry, {
      provider
    });

    const result = await registry.invokeResult<{
      providerName: string;
      queryLength: number;
      maxResults: number;
      resultCount: number;
      results: Array<{
        title: string;
        url: string;
        snippet?: string;
        source?: string;
      }>;
    }>(
      {
        toolName: toolName("web.search"),
        input: {
          query: "Dominic Nexus architecture",
          maxResults: 2
        }
      },
      { policy }
    );

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value.output).toEqual({
        providerName: "mock-search",
        queryLength: "Dominic Nexus architecture".length,
        maxResults: 2,
        resultCount: 1,
        results: [
          {
            title: "Dominic Nexus",
            url: "https://example.test/nexus?tracking=allowed",
            snippet: "project notes",
            source: "example.test"
          }
        ]
      });
    }
    expect(provider.search).toHaveBeenCalledWith({
      query: "Dominic Nexus architecture",
      maxResults: 2
    }, {});
    expect(policy.requests.map((request) => request.action)).toEqual(["network.request", "network.request"]);
    expect(policy.requests[1]).toEqual(
      expect.objectContaining({
        action: "network.request",
        resource: "web.search:mock-search",
        metadata: expect.objectContaining({
          providerName: "mock-search",
          queryLength: "Dominic Nexus architecture".length,
          maxResults: 2
        })
      })
    );
  });

  it("passes caller abort signals to the injected web search provider after authorization", async () => {
    const policy = new RecordingPolicy();
    const registry = new ToolRegistry();
    const provider = createRecordingWebSearchProvider();
    const controller = new AbortController();

    registerWebSearchTool(registry, {
      provider
    });

    const result = await registry.invokeResult(
      {
        toolName: toolName("web.search"),
        input: {
          query: "signal propagation"
        }
      },
      {
        policy,
        signal: controller.signal
      }
    );

    expect(result.ok).toBe(true);
    expect(provider.contexts).toEqual([
      {
        signal: controller.signal
      }
    ]);
  });

  it("does not reach web search provider when default policy denies registry-level network permission", async () => {
    const policy = new RecordingPolicy({ allowed: false, reason: "blocked" });
    const registry = new ToolRegistry();
    const provider = createRecordingWebSearchProvider();

    registerWebSearchTool(registry, {
      provider
    });

    const result = await registry.invokeResult(
      {
        toolName: toolName("web.search"),
        input: {
          query: "blocked search"
        }
      },
      { policy }
    );

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(serializeAppError(result.error)).toEqual({
        name: "AppError",
        code: "tool.permission_denied",
        message: "Tool permission denied: web.search",
        context: {
          action: "network.request",
          toolName: "web.search"
        }
      });
    }
    expect(policy.requests).toHaveLength(1);
    expect(provider.search).not.toHaveBeenCalled();
  });

  it("does not reach web search provider when handler-level network authorization denies the provider", async () => {
    const policy = new SequencedPolicy([{ allowed: true }, { allowed: false, reason: "blocked search provider" }]);
    const registry = new ToolRegistry();
    const provider = createRecordingWebSearchProvider();

    registerWebSearchTool(registry, {
      provider
    });

    const result = await registry.invokeResult(
      {
        toolName: toolName("web.search"),
        input: {
          query: "handler denied"
        }
      },
      { policy }
    );

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(serializeAppError(result.error)).toEqual({
        name: "AppError",
        code: "permission.denied",
        message: "Network request permission denied",
        context: {
          action: "network.request",
          resource: "web.search:mock-search"
        }
      });
    }
    expect(policy.requests.map((request) => request.action)).toEqual(["network.request", "network.request"]);
    expect(provider.search).not.toHaveBeenCalled();
  });

  it("rejects invalid web search input before permissions or provider calls", async () => {
    const policy = new RecordingPolicy();
    const registry = new ToolRegistry();
    const provider = createRecordingWebSearchProvider();

    registerWebSearchTool(registry, {
      provider
    });

    for (const input of [
      {
        query: "",
        maxResults: 1
      },
      {
        query: "bad\0query"
      },
      {
        query: "valid",
        unexpected: true
      }
    ]) {
      const result = await registry.invokeResult(
        {
          toolName: toolName("web.search"),
          input
        },
        { policy }
      );

      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.error.code).toBe("tool.invalid_input");
      }
    }

    expect(policy.requests).toHaveLength(0);
    expect(provider.search).not.toHaveBeenCalled();
  });

  it("rejects invalid web search provider names during registration", () => {
    const invalidProviders = [
      {
        ...createRecordingWebSearchProvider(),
        name: ""
      },
      {
        ...createRecordingWebSearchProvider(),
        name: "bad\0provider"
      },
      {
        ...createRecordingWebSearchProvider(),
        name: "p".repeat(121)
      }
    ];

    for (const provider of invalidProviders) {
      const registry = new ToolRegistry();

      expect(() =>
        registerWebSearchTool(registry, {
          provider
        })
      ).toThrow(AppError);
      expect(registry.get(toolName("web.search"))).toBeUndefined();
    }
  });

  it("validates web search result limits and bounds provider output", async () => {
    const policy = new RecordingPolicy();
    const registry = new ToolRegistry();
    const provider = createRecordingWebSearchProvider({
      providerName: "mock-search",
      results: [
        {
          title: "One",
          url: "https://example.test/one"
        },
        {
          title: "Two",
          url: "https://example.test/two"
        },
        {
          title: "Three",
          url: "https://example.test/three"
        }
      ]
    });

    registerWebSearchTool(registry, {
      provider,
      defaultMaxResults: 2,
      absoluteMaxResults: 3
    });

    const tooMany = await registry.invokeResult(
      {
        toolName: toolName("web.search"),
        input: {
          query: "limit test",
          maxResults: 4
        }
      },
      { policy }
    );
    expect(tooMany.ok).toBe(false);
    if (!tooMany.ok) {
      expect(tooMany.error.code).toBe("tool.invalid_input");
    }

    const result = await registry.invokeResult<{
      maxResults: number;
      resultCount: number;
      results: Array<{ title: string }>;
    }>(
      {
        toolName: toolName("web.search"),
        input: {
          query: "limit test",
          maxResults: 2
        }
      },
      { policy }
    );

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value.output.maxResults).toBe(2);
      expect(result.value.output.resultCount).toBe(2);
      expect(result.value.output.results.map((item) => item.title)).toEqual(["One", "Two"]);
    }
    expect(provider.search).toHaveBeenCalledOnce();
  });

  it("audits web search safe metadata without query text or result snippets", async () => {
    const { audit, context } = createAuditContext();
    const policy = new RecordingPolicy();
    const registry = new ToolRegistry();
    const provider = createRecordingWebSearchProvider({
      providerName: "mock-search",
      results: [
        {
          title: "Sensitive remote title",
          url: "https://example.test/secret-result",
          snippet: "TOP-SECRET-REMOTE-SNIPPET"
        }
      ]
    });

    registerWebSearchTool(registry, {
      provider
    });

    const result = await registry.invokeResult(
      {
        toolName: toolName("web.search"),
        input: {
          query: "sensitive local search token",
          maxResults: 1
        }
      },
      { policy, audit: context }
    );

    expect(result.ok).toBe(true);
    const events = audit.listEvents();
    const webSearchEvent = events.find((event) => event.action === "web.search" && event.outcome === "succeeded");
    expect(webSearchEvent).toMatchObject({
      action: "web.search",
      decision: "allowed",
      outcome: "succeeded"
    });
    expect(webSearchEvent?.metadata).toEqual({
      operation: "search",
      providerName: "mock-search",
      queryLength: "sensitive local search token".length,
      maxResults: 1,
      resultCount: 1,
      errorCode: null
    });
    expect(JSON.stringify(events)).not.toContain("sensitive local search token");
    expect(JSON.stringify(events)).not.toContain("TOP-SECRET-REMOTE-SNIPPET");
    expect(JSON.stringify(events)).not.toContain("Sensitive remote title");
  });

  it("executes shell commands through invokeResult using an injected executor", async () => {
    const policy = new RecordingPolicy();
    const registry = new ToolRegistry();
    const executor = createRecordingShellExecutor();

    registerShellTool(registry, {
      executor,
      defaultCwd: "C:\\workspace",
      platform: "win32",
      defaultShell: "powershell",
      defaultTimeoutMs: 1000,
      absoluteTimeoutMs: 5000,
      defaultMaxOutputBytes: 128,
      absoluteMaxOutputBytes: 1024
    });

    const result = await registry.invokeResult<{
      status: "completed";
      exitCode: number | null;
      stdout: string;
    }>(
      {
        toolName: toolName("shell.execute"),
        input: {
          command: "echo ok",
          cwd: "C:\\workspace\\project",
          env: {
            DOMINIC_NEXUS_MODE: "test"
          },
          timeoutMs: 2000,
          maxOutputBytes: 64,
          shell: "cmd"
        }
      },
      { policy }
    );

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value.output).toMatchObject({
        status: "completed",
        exitCode: 0,
        stdout: "shell stdout",
        stderr: "",
        stdoutBytes: Buffer.byteLength("shell stdout"),
        stderrBytes: 0,
        stdoutTruncated: false,
        stderrTruncated: false
      });
    }
    expect(policy.requests.map((request) => request.action)).toEqual(["shell.execute", "shell.execute"]);
    expect(executor.execute).toHaveBeenCalledOnce();
    expect(executor.requests[0]).toEqual({
      command: "echo ok",
      cwd: "C:\\workspace\\project",
      env: {
        DOMINIC_NEXUS_MODE: "test"
      },
      timeoutMs: 2000,
      shell: "cmd",
      platform: "win32",
      maxStdoutBytes: 64,
      maxStderrBytes: 64
    });
  });

  it("does not spawn shell commands when default policy denies registry-level shell permission", async () => {
    const policy = new RecordingPolicy({ allowed: false, reason: "blocked" });
    const registry = new ToolRegistry();
    const executor = createRecordingShellExecutor();

    registerShellTool(registry, {
      executor,
      defaultCwd: "C:\\workspace",
      platform: "win32"
    });

    const result = await registry.invokeResult(
      {
        toolName: toolName("shell.execute"),
        input: {
          command: "echo blocked"
        }
      },
      { policy }
    );

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(serializeAppError(result.error)).toEqual({
        name: "AppError",
        code: "tool.permission_denied",
        message: "Tool permission denied: shell.execute",
        context: {
          action: "shell.execute",
          toolName: "shell.execute"
        }
      });
    }
    expect(policy.requests).toHaveLength(1);
    expect(executor.execute).not.toHaveBeenCalled();
  });

  it("does not spawn shell commands when handler-level shell authorization denies execution", async () => {
    const policy = new SequencedPolicy([{ allowed: true }, { allowed: false, reason: "blocked by shell policy" }]);
    const registry = new ToolRegistry();
    const executor = createRecordingShellExecutor();

    registerShellTool(registry, {
      executor,
      defaultCwd: "C:\\workspace",
      platform: "win32"
    });

    const result = await registry.invokeResult(
      {
        toolName: toolName("shell.execute"),
        input: {
          command: "echo handler-denied"
        }
      },
      { policy }
    );

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(serializeAppError(result.error)).toEqual({
        name: "AppError",
        code: "permission.denied",
        message: "Shell execution permission denied",
        context: {
          action: "shell.execute",
          command: "echo handler-denied"
        }
      });
    }
    expect(policy.requests.map((request) => request.action)).toEqual(["shell.execute", "shell.execute"]);
    expect(executor.execute).not.toHaveBeenCalled();
  });

  it("does not inherit parent process env and merges only explicit shell base env plus input env", async () => {
    const previousSecret = process.env.DOMINIC_NEXUS_PARENT_ONLY_SECRET;
    process.env.DOMINIC_NEXUS_PARENT_ONLY_SECRET = "parent-secret";
    const policy = new RecordingPolicy();
    const registry = new ToolRegistry();
    const executor = createRecordingShellExecutor();

    try {
      registerShellTool(registry, {
        executor,
        defaultCwd: "C:\\workspace",
        platform: "win32",
        baseEnv: {
          SAFE_BASE_ENV: "base"
        }
      });

      const result = await registry.invokeResult(
        {
          toolName: toolName("shell.execute"),
          input: {
            command: "echo env",
            env: {
              SAFE_INPUT_ENV: "input"
            }
          }
        },
        { policy }
      );

      expect(result.ok).toBe(true);
      expect(executor.requests[0]?.env).toEqual({
        SAFE_BASE_ENV: "base",
        SAFE_INPUT_ENV: "input"
      });
      expect(JSON.stringify(executor.requests[0]?.env)).not.toContain("parent-secret");
    } finally {
      if (previousSecret === undefined) {
        delete process.env.DOMINIC_NEXUS_PARENT_ONLY_SECRET;
      } else {
        process.env.DOMINIC_NEXUS_PARENT_ONLY_SECRET = previousSecret;
      }
    }
  });

  it("rejects risky shell base env during registration", () => {
    const registry = new ToolRegistry();

    expect(() =>
      registerShellTool(registry, {
        executor: createRecordingShellExecutor(),
        defaultCwd: "C:\\workspace",
        platform: "win32",
        baseEnv: {
          PATH: "unsafe"
        }
      })
    ).toThrow(AppError);
    expect(registry.get(toolName("shell.execute"))).toBeUndefined();
  });

  it("normalizes shell cwd to an approved absolute root before authorization and spawn", async () => {
    const policy = new RecordingPolicy();
    const registry = new ToolRegistry();
    const executor = createRecordingShellExecutor();

    registerShellTool(registry, {
      executor,
      defaultCwd: "C:\\workspace",
      cwdRoots: ["C:\\workspace"],
      platform: "win32"
    });

    const result = await registry.invokeResult(
      {
        toolName: toolName("shell.execute"),
        input: {
          command: "echo cwd",
          cwd: "project\\subdir"
        }
      },
      { policy }
    );

    expect(result.ok).toBe(true);
    expect(policy.requests[1]).toEqual(
      expect.objectContaining({
        action: "shell.execute",
        metadata: expect.objectContaining({
          cwd: "C:\\workspace\\project\\subdir"
        })
      })
    );
    expect(executor.requests[0]).toEqual(
      expect.objectContaining({
        cwd: "C:\\workspace\\project\\subdir"
      })
    );
  });

  it("rejects shell cwd outside approved roots before permissions or executor spawn", async () => {
    const policy = new RecordingPolicy();
    const registry = new ToolRegistry();
    const executor = createRecordingShellExecutor();

    registerShellTool(registry, {
      executor,
      defaultCwd: "C:\\workspace\\allowed",
      cwdRoots: ["C:\\workspace\\allowed"],
      platform: "win32"
    });

    const result = await registry.invokeResult(
      {
        toolName: toolName("shell.execute"),
        input: {
          command: "echo outside",
          cwd: "C:\\workspace\\other"
        }
      },
      { policy }
    );

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe("tool.invalid_input");
    }
    expect(policy.requests).toHaveLength(0);
    expect(executor.execute).not.toHaveBeenCalled();
  });

  it("passes caller abort signals to the shell executor after authorization", async () => {
    const policy = new RecordingPolicy();
    const registry = new ToolRegistry();
    const executor = createRecordingShellExecutor();
    const controller = new AbortController();

    registerShellTool(registry, {
      executor,
      defaultCwd: "C:\\workspace",
      platform: "win32"
    });

    const result = await registry.invokeResult(
      {
        toolName: toolName("shell.execute"),
        input: {
          command: "echo signal"
        }
      },
      {
        policy,
        signal: controller.signal
      }
    );

    expect(result.ok).toBe(true);
    expect(executor.requests[0]).toEqual(
      expect.objectContaining({
        signal: controller.signal
      })
    );
  });

  it("rejects invalid shell input before permissions or executor spawn", async () => {
    const policy = new RecordingPolicy();
    const registry = new ToolRegistry();
    const executor = createRecordingShellExecutor();

    registerShellTool(registry, {
      executor,
      defaultCwd: "C:\\workspace",
      platform: "win32"
    });

    const result = await registry.invokeResult(
      {
        toolName: toolName("shell.execute"),
        input: {
          command: "",
          unexpected: true
        }
      },
      { policy }
    );

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe("tool.invalid_input");
    }
    expect(policy.requests).toHaveLength(0);
    expect(executor.execute).not.toHaveBeenCalled();
  });

  it("rejects risky shell env overrides before permissions or executor spawn", async () => {
    const policy = new RecordingPolicy();
    const registry = new ToolRegistry();
    const executor = createRecordingShellExecutor();

    registerShellTool(registry, {
      executor,
      defaultCwd: "C:\\workspace",
      platform: "win32"
    });

    for (const key of ["PATH", "LD_PRELOAD", "DYLD_INSERT_LIBRARIES"]) {
      const result = await registry.invokeResult(
        {
          toolName: toolName("shell.execute"),
          input: {
            command: "echo env",
            env: {
              [key]: "unsafe"
            }
          }
        },
        { policy }
      );

      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.error.code).toBe("tool.invalid_input");
      }
    }
    expect(policy.requests).toHaveLength(0);
    expect(executor.execute).not.toHaveBeenCalled();
  });

  it("passes shell timeout and output limits to the executor and validates configured bounds", async () => {
    const policy = new RecordingPolicy();
    const registry = new ToolRegistry();
    const executor = createRecordingShellExecutor({
      status: "completed",
      exitCode: 0,
      signal: null,
      stdout: "ok",
      stderr: "",
      stdoutBytes: Buffer.byteLength("ok"),
      stderrBytes: 0,
      stdoutTruncated: false,
      stderrTruncated: false
    });

    registerShellTool(registry, {
      executor,
      defaultCwd: "C:\\workspace",
      platform: "win32",
      defaultTimeoutMs: 1500,
      absoluteTimeoutMs: 2000,
      defaultMaxOutputBytes: 7,
      absoluteMaxOutputBytes: 8
    });

    const invalid = await registry.invokeResult(
      {
        toolName: toolName("shell.execute"),
        input: {
          command: "echo too-much",
          timeoutMs: 2001,
          maxOutputBytes: 9
        }
      },
      { policy }
    );
    expect(invalid.ok).toBe(false);
    if (!invalid.ok) {
      expect(invalid.error.code).toBe("tool.invalid_input");
    }

    const valid = await registry.invokeResult(
      {
        toolName: toolName("shell.execute"),
        input: {
          command: "echo default-limits"
        }
      },
      { policy }
    );
    expect(valid.ok).toBe(true);
    expect(executor.requests[0]).toEqual(
      expect.objectContaining({
        timeoutMs: 1500,
        maxStdoutBytes: 7,
        maxStderrBytes: 7
      })
    );
  });

  it("rejects shell executor output that exceeds the configured output limit", async () => {
    const policy = new RecordingPolicy();
    const registry = new ToolRegistry();
    const executor = createRecordingShellExecutor({
      status: "completed",
      exitCode: 0,
      signal: null,
      stdout: "too much output",
      stderr: "",
      stdoutBytes: Buffer.byteLength("too much output"),
      stderrBytes: 0,
      stdoutTruncated: false,
      stderrTruncated: false
    });

    registerShellTool(registry, {
      executor,
      defaultCwd: "C:\\workspace",
      platform: "win32",
      defaultMaxOutputBytes: 4,
      absoluteMaxOutputBytes: 4
    });

    const result = await registry.invokeResult(
      {
        toolName: toolName("shell.execute"),
        input: {
          command: "echo excessive"
        }
      },
      { policy }
    );

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(serializeAppError(result.error)).toEqual({
        name: "AppError",
        code: "tool.execution_failed",
        message: "Shell executor returned output beyond configured limits",
        context: {
          maxOutputBytes: 4,
          stdoutBytes: Buffer.byteLength("too much output"),
          stderrBytes: 0
        }
      });
    }
  });

  it("audits shell metadata without env values or raw stdout and stderr", async () => {
    const { audit, context } = createAuditContext();
    const policy = new RecordingPolicy();
    const registry = new ToolRegistry();
    const executor = createRecordingShellExecutor({
      status: "completed",
      exitCode: 0,
      signal: null,
      stdout: "RAW-STDOUT-SECRET",
      stderr: "RAW-STDERR-SECRET",
      stdoutBytes: Buffer.byteLength("RAW-STDOUT-SECRET"),
      stderrBytes: Buffer.byteLength("RAW-STDERR-SECRET"),
      stdoutTruncated: false,
      stderrTruncated: false
    });

    registerShellTool(registry, {
      executor,
      defaultCwd: "C:\\workspace",
      platform: "win32"
    });

    const result = await registry.invokeResult(
      {
        toolName: toolName("shell.execute"),
        input: {
          command: "echo safe-audit-command",
          env: {
            SAFE_ENV: "ENV-VALUE-SECRET"
          },
          maxOutputBytes: 64
        }
      },
      { policy, audit: context }
    );

    expect(result.ok).toBe(true);
    expect(audit.listEvents()).toContainEqual(
      expect.objectContaining({
        action: "shell.execute",
        decision: "allowed",
        outcome: "succeeded",
        metadata: expect.objectContaining({
          command: "echo safe-audit-command",
          cwd: "C:\\workspace",
          envKeys: ["SAFE_ENV"],
          timeoutMs: 30000,
          maxOutputBytes: 64,
          shell: "powershell",
          platform: "win32",
          status: "completed",
          exitCode: 0,
          signal: null,
          stdoutBytes: Buffer.byteLength("RAW-STDOUT-SECRET"),
          stderrBytes: Buffer.byteLength("RAW-STDERR-SECRET"),
          stdoutTruncated: false,
          stderrTruncated: false
        })
      })
    );
    expect(JSON.stringify(audit.listEvents())).not.toContain("RAW-STDOUT-SECRET");
    expect(JSON.stringify(audit.listEvents())).not.toContain("RAW-STDERR-SECRET");
    expect(JSON.stringify(audit.listEvents())).not.toContain("ENV-VALUE-SECRET");
  });

  it("exposes read file metadata only and does not export the raw tool", () => {
    const registry = new ToolRegistry();

    registerReadFileTool(registry, {
      filesystem: createWindowsFilesystemRootPolicy()
    });

    expect(registry.get(toolName("filesystem.read_file"))).toEqual({
      name: "filesystem.read_file",
      description: "Reads a UTF-8 text file under approved filesystem roots.",
      inputSchema: expect.objectContaining({
        name: "filesystem.read_file.input",
        kind: "object"
      }),
      outputSchema: expect.objectContaining({
        name: "filesystem.read_file.output",
        kind: "object"
      }),
      requiredPermissions: ["filesystem.read"]
    });
    expect(registry.get(toolName("filesystem.read_file"))).not.toHaveProperty("execute");
    expect(registry.get(toolName("filesystem.read_file"))?.inputSchema).not.toHaveProperty("validate");
    expect(toolsExports).not.toHaveProperty("readFileTool");
  });

  it("exposes write file metadata only and does not export the raw tool", () => {
    const registry = new ToolRegistry();

    registerWriteFileTool(registry, {
      filesystem: createWindowsFilesystemRootPolicy()
    });

    expect(registry.get(toolName("filesystem.write_file"))).toEqual({
      name: "filesystem.write_file",
      description: "Writes a UTF-8 text file under approved filesystem roots with explicit create or overwrite mode.",
      inputSchema: expect.objectContaining({
        name: "filesystem.write_file.input",
        kind: "object"
      }),
      outputSchema: expect.objectContaining({
        name: "filesystem.write_file.output",
        kind: "object"
      }),
      requiredPermissions: ["filesystem.write"]
    });
    expect(registry.get(toolName("filesystem.write_file"))).not.toHaveProperty("execute");
    expect(registry.get(toolName("filesystem.write_file"))?.inputSchema).not.toHaveProperty("validate");
    expect(toolsExports).not.toHaveProperty("writeFileTool");
  });

  it("exposes web fetch metadata only and does not export the raw tool", () => {
    const registry = new ToolRegistry();

    registerWebFetchTool(registry, {
      transport: createRecordingWebFetchTransport()
    });

    expect(registry.get(toolName("web.fetch"))).toEqual({
      name: "web.fetch",
      description: "Fetches HTTP(S) text content after explicit network request authorization.",
      inputSchema: expect.objectContaining({
        name: "web.fetch.input",
        kind: "object"
      }),
      outputSchema: expect.objectContaining({
        name: "web.fetch.output",
        kind: "object"
      }),
      requiredPermissions: ["network.request"]
    });
    expect(registry.get(toolName("web.fetch"))).not.toHaveProperty("execute");
    expect(registry.get(toolName("web.fetch"))?.inputSchema).not.toHaveProperty("validate");
    expect(toolsExports).not.toHaveProperty("webFetchTool");
  });

  it("exposes web search metadata only and does not export the raw tool", () => {
    const registry = new ToolRegistry();

    registerWebSearchTool(registry, {
      provider: createRecordingWebSearchProvider()
    });

    expect(registry.get(toolName("web.search"))).toEqual({
      name: "web.search",
      description: "Runs web search through an injected provider after explicit network request authorization.",
      inputSchema: expect.objectContaining({
        name: "web.search.input",
        kind: "object"
      }),
      outputSchema: expect.objectContaining({
        name: "web.search.output",
        kind: "object"
      }),
      requiredPermissions: ["network.request"]
    });
    expect(registry.get(toolName("web.search"))).not.toHaveProperty("execute");
    expect(registry.get(toolName("web.search"))?.inputSchema).not.toHaveProperty("validate");
    expect(toolsExports).not.toHaveProperty("webSearchTool");
    expect(toolsExports).not.toHaveProperty("createWebSearchTool");
  });

  it("exposes shell metadata only and does not export the raw tool", () => {
    const registry = new ToolRegistry();

    registerShellTool(registry, {
      executor: createRecordingShellExecutor(),
      defaultCwd: "C:\\workspace",
      platform: "win32"
    });

    expect(registry.get(toolName("shell.execute"))).toEqual({
      name: "shell.execute",
      description: "Executes an explicitly approved shell command with bounded cwd, env, timeout, and output.",
      inputSchema: expect.objectContaining({
        name: "shell.execute.input",
        kind: "object"
      }),
      outputSchema: expect.objectContaining({
        name: "shell.execute.output",
        kind: "object"
      }),
      requiredPermissions: ["shell.execute"]
    });
    expect(registry.get(toolName("shell.execute"))).not.toHaveProperty("execute");
    expect(registry.get(toolName("shell.execute"))?.inputSchema).not.toHaveProperty("validate");
    expect(toolsExports).not.toHaveProperty("shellTool");
    expect(toolsExports).not.toHaveProperty("createShellTool");
  });

  it("returns metadata-only lookup results without exposing handlers", () => {
    const registry = new ToolRegistry();

    registry.register({
      name: toolName("metadata-only"),
      description: "Metadata only",
      inputSchema: stringSchema,
      outputSchema: stringSchema,
      requiredPermissions: ["network.request"],
      execute(input: string) {
        return input;
      }
    });

    expect(registry.get(toolName("metadata-only"))).toEqual({
      name: "metadata-only",
      description: "Metadata only",
      inputSchema: expect.objectContaining({
        name: "test.string",
        kind: "string"
      }),
      outputSchema: expect.objectContaining({
        name: "test.string",
        kind: "string"
      }),
      requiredPermissions: ["network.request"]
    });
    expect(registry.get(toolName("metadata-only"))).not.toHaveProperty("execute");
  });

  it("registers and executes a tool after checking required permissions", async () => {
    const policy = new RecordingPolicy();
    const registry = new ToolRegistry();
    const execute = vi.fn((input: string) => input.toUpperCase());
    const tool: ToolDefinition<string, string> = {
      name: toolName("uppercase"),
      description: "Uppercase text",
      inputSchema: stringSchema,
      outputSchema: stringSchema,
      requiredPermissions: ["filesystem.read", "network.request"],
      execute
    };

    registry.register(tool);

    await expect(
      registry.execute<string, string>(toolName("uppercase"), "hello", {
        policy,
        metadata: { traceId: "test-trace" }
      })
    ).resolves.toBe("HELLO");

    expect(execute).toHaveBeenCalledOnce();
    expect(policy.requests).toEqual([
      {
        action: "filesystem.read",
        reason: "Execute tool: uppercase",
        resource: "uppercase",
        metadata: { traceId: "test-trace" }
      },
      {
        action: "network.request",
        reason: "Execute tool: uppercase",
        resource: "uppercase",
        metadata: { traceId: "test-trace" }
      }
    ]);
  });

  it("returns a normalized invocation response from the central pipeline", async () => {
    const policy = new RecordingPolicy();
    const registry = new ToolRegistry();

    registry.register({
      name: toolName("normalize"),
      description: "Normalize response",
      inputSchema: stringSchema,
      outputSchema: stringSchema,
      requiredPermissions: [],
      execute(input: string) {
        return input.toUpperCase();
      }
    });

    const result = await registry.invokeResult<string>(
      {
        toolName: toolName("normalize"),
        input: "hello",
        metadata: { traceId: "trace-normalized" }
      },
      { policy }
    );

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value).toEqual({
        toolName: "normalize",
        output: "HELLO",
        metadata: expect.objectContaining({
          inputSchema: expect.objectContaining({ name: "test.string", kind: "string" }),
          outputSchema: expect.objectContaining({ name: "test.string", kind: "string" }),
          requiredPermissions: [],
          traceId: "trace-normalized"
        })
      });
    }
  });

  it("audits allowed tool execution and redacts permission metadata", async () => {
    const { audit, context } = createAuditContext();
    const policy = new RecordingPolicy();
    const registry = new ToolRegistry();

    registry.register({
      name: toolName("audited-tool"),
      description: "Audited tool",
      inputSchema: stringSchema,
      outputSchema: stringSchema,
      requiredPermissions: ["network.request"],
      execute(input: string) {
        return input;
      }
    });

    await expect(
      registry.execute(toolName("audited-tool"), "ok", {
        policy,
        audit: context,
        metadata: {
          traceId: "trace-1",
          authorization: "Bearer secret-token"
        }
      })
    ).resolves.toBe("ok");

    const events = audit.listEvents();
    expect(events).toHaveLength(3);
    expect(events[0]).toMatchObject({
      action: "tool.execute",
      decision: "pending",
      outcome: "requested",
      metadata: {
        traceId: "trace-1",
        authorization: REDACTED_PLACEHOLDER,
        inputSchema: {
          name: "test.string",
          kind: "string"
        },
        outputSchema: {
          name: "test.string",
          kind: "string"
        },
        requiredPermissions: ["network.request"]
      }
    });
    expect(events[1]).toMatchObject({
      action: "permission.decide",
      decision: "allowed",
      outcome: "succeeded",
      metadata: {
        requestMetadata: {
          traceId: "trace-1",
          authorization: REDACTED_PLACEHOLDER
        }
      }
    });
    expect(events[2]).toMatchObject({
      action: "tool.execute",
      decision: "allowed",
      outcome: "succeeded",
      resource: {
        type: "tool",
        id: "audited-tool"
      },
      metadata: {
        requiredPermissions: ["network.request"]
      }
    });
    expect(JSON.stringify(events)).not.toContain("secret-token");
  });

  it("validates input before permissions and handler execution", async () => {
    const { audit, context } = createAuditContext();
    const policy = new RecordingPolicy();
    const registry = new ToolRegistry();
    const execute = vi.fn();

    registry.register({
      name: toolName("string-input"),
      description: "Requires string input",
      inputSchema: stringSchema,
      outputSchema: stringSchema,
      requiredPermissions: ["network.request"],
      execute
    });

    const result = await registry.executeResult(toolName("string-input"), { token: "raw-secret-value" }, { policy, audit: context });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(serializeAppError(result.error)).toEqual({
        name: "AppError",
        code: "tool.invalid_input",
        message: "Tool input validation failed: string-input",
        context: {
          toolName: "string-input",
          schemaName: "test.string",
          schemaKind: "string",
          validationCode: "tool.invalid_input"
        }
      });
    }
    expect(policy.requests).toHaveLength(0);
    expect(execute).not.toHaveBeenCalled();
    expect(audit.listEvents()).toEqual([
      expect.objectContaining({
        action: "tool.execute",
        decision: "pending",
        outcome: "requested"
      }),
      expect.objectContaining({
        action: "tool.execute",
        decision: "not_applicable",
        outcome: "failed",
        metadata: expect.objectContaining({
          validationPhase: "input",
          errorCode: "tool.invalid_input"
        })
      })
    ]);
    expect(JSON.stringify(audit.listEvents())).not.toContain("raw-secret-value");
  });

  it("validates output and avoids logging raw output", async () => {
    const { audit, context } = createAuditContext();
    const policy = new RecordingPolicy();
    const registry = new ToolRegistry();

    registry.register({
      name: toolName("bad-output"),
      description: "Returns non JSON output",
      inputSchema: stringSchema,
      outputSchema: jsonSchema,
      requiredPermissions: [],
      execute() {
        return { token: "raw-secret-value", value: undefined } as unknown as JsonValue;
      }
    });

    const result = await registry.executeResult(toolName("bad-output"), "ok", { policy, audit: context });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(serializeAppError(result.error)).toEqual({
        name: "AppError",
        code: "tool.invalid_output",
        message: "Tool output validation failed: bad-output",
        context: {
          toolName: "bad-output",
          schemaName: "test.json",
          schemaKind: "json",
          validationCode: "tool.invalid_input"
        }
      });
    }
    expect(audit.listEvents()).toEqual([
      expect.objectContaining({
        action: "tool.execute",
        decision: "pending",
        outcome: "requested"
      }),
      expect.objectContaining({
        action: "tool.execute",
        decision: "allowed",
        outcome: "failed",
        metadata: expect.objectContaining({
          validationPhase: "output",
          errorCode: "tool.invalid_output"
        })
      })
    ]);
    expect(JSON.stringify(audit.listEvents())).not.toContain("raw-secret-value");
  });

  it("sanitizes thrown input schema validator errors", async () => {
    const { audit, context } = createAuditContext();
    const policy = new RecordingPolicy();
    const registry = new ToolRegistry();
    const execute = vi.fn();
    const throwingInputSchema = createToolSchema({
      name: "test.throwing-input",
      kind: "object",
      validate() {
        throw new Error("validator leaked raw-secret-value");
      }
    });

    registry.register({
      name: toolName("throwing-input-validator"),
      description: "Throws during input validation",
      inputSchema: throwingInputSchema,
      outputSchema: jsonSchema,
      requiredPermissions: ["network.request"],
      execute
    });

    const result = await registry.executeResult(toolName("throwing-input-validator"), {}, { policy, audit: context });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(serializeAppError(result.error)).toEqual({
        name: "AppError",
        code: "tool.invalid_input",
        message: "Tool input validation failed: throwing-input-validator",
        context: {
          toolName: "throwing-input-validator",
          schemaName: "test.throwing-input",
          schemaKind: "object"
        }
      });
    }
    expect(policy.requests).toHaveLength(0);
    expect(execute).not.toHaveBeenCalled();
    expect(JSON.stringify(audit.listEvents())).not.toContain("raw-secret-value");
  });

  it("sanitizes thrown output schema validator errors", async () => {
    const { audit, context } = createAuditContext();
    const policy = new RecordingPolicy();
    const registry = new ToolRegistry();
    const throwingOutputSchema = createToolSchema({
      name: "test.throwing-output",
      kind: "object",
      validate() {
        throw new Error("validator leaked raw-secret-value");
      }
    });

    registry.register({
      name: toolName("throwing-output-validator"),
      description: "Throws during output validation",
      inputSchema: jsonSchema,
      outputSchema: throwingOutputSchema,
      requiredPermissions: [],
      execute() {
        return {};
      }
    });

    const result = await registry.executeResult(toolName("throwing-output-validator"), {}, { policy, audit: context });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(serializeAppError(result.error)).toEqual({
        name: "AppError",
        code: "tool.invalid_output",
        message: "Tool output validation failed: throwing-output-validator",
        context: {
          toolName: "throwing-output-validator",
          schemaName: "test.throwing-output",
          schemaKind: "object"
        }
      });
    }
    expect(JSON.stringify(audit.listEvents())).not.toContain("raw-secret-value");
  });

  it("returns a safe AppError and does not execute when permission is denied", async () => {
    const policy = new RecordingPolicy({ allowed: false, reason: "blocked" });
    const registry = new ToolRegistry();
    const execute = vi.fn();

    registry.register({
      name: toolName("blocked-tool"),
      description: "Blocked tool",
      inputSchema: jsonSchema,
      outputSchema: jsonSchema,
      requiredPermissions: ["shell.execute"],
      execute
    });

    const result = await registry.executeResult(toolName("blocked-tool"), {}, { policy });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(serializeAppError(result.error)).toEqual({
        name: "AppError",
        code: "tool.permission_denied",
        message: "Tool permission denied: blocked-tool",
        context: {
          action: "shell.execute",
          toolName: "blocked-tool"
        }
      });
    }
    await expect(registry.execute(toolName("blocked-tool"), {}, { policy })).rejects.toMatchObject({
      code: "tool.permission_denied"
    });

    expect(execute).not.toHaveBeenCalled();
    expect(policy.requests).toHaveLength(2);
    expect(policy.requests[0]?.action).toBe("shell.execute");
  });

  it("audits denied tool permission decisions", async () => {
    const { audit, context } = createAuditContext();
    const policy = new RecordingPolicy({ allowed: false, reason: "blocked" });
    const registry = new ToolRegistry();
    const execute = vi.fn();

    registry.register({
      name: toolName("denied-tool"),
      description: "Denied tool",
      inputSchema: jsonSchema,
      outputSchema: jsonSchema,
      requiredPermissions: ["shell.execute"],
      execute
    });

    const result = await registry.executeResult(toolName("denied-tool"), {}, { policy, audit: context });

    expect(result.ok).toBe(false);
    expect(execute).not.toHaveBeenCalled();
    expect(audit.listEvents()).toEqual([
      expect.objectContaining({
        action: "tool.execute",
        decision: "pending",
        outcome: "requested",
        resource: expect.objectContaining({
          id: "denied-tool"
        })
      }),
      expect.objectContaining({
        action: "permission.decide",
        decision: "denied",
        outcome: "denied"
      }),
      expect.objectContaining({
        action: "tool.execute",
        decision: "denied",
        outcome: "denied",
        resource: expect.objectContaining({
          id: "denied-tool"
        })
      })
    ]);
  });

  it("audits tool permission check failures without executing the tool", async () => {
    const { audit, context } = createAuditContext();
    const registry = new ToolRegistry();
    const execute = vi.fn();

    registry.register({
      name: toolName("policy-failure-tool"),
      description: "Policy failure tool",
      inputSchema: jsonSchema,
      outputSchema: jsonSchema,
      requiredPermissions: ["network.request"],
      execute
    });

    const result = await registry.executeResult(toolName("policy-failure-tool"), {}, {
      policy: new ThrowingPolicy(),
      audit: context
    });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(serializeAppError(result.error)).toEqual({
        name: "AppError",
        code: "tool.execution_failed",
        message: "Tool permission check failed: policy-failure-tool",
        context: {
          toolName: "policy-failure-tool"
        }
      });
    }
    expect(execute).not.toHaveBeenCalled();
    expect(audit.listEvents()).toEqual([
      expect.objectContaining({
        action: "tool.execute",
        decision: "pending",
        outcome: "requested",
        resource: expect.objectContaining({
          id: "policy-failure-tool"
        })
      }),
      expect.objectContaining({
        action: "tool.execute",
        decision: "not_applicable",
        outcome: "failed",
        resource: expect.objectContaining({
          id: "policy-failure-tool"
        }),
        metadata: {
          permission: "network.request",
          errorName: "Error"
        }
      })
    ]);
    expect(JSON.stringify(audit.listEvents())).not.toContain("secret-token");
  });

  it("throws for unknown tools", async () => {
    const registry = new ToolRegistry();
    const policy = new RecordingPolicy();

    await expect(registry.execute(toolName("missing"), {}, { policy })).rejects.toThrow("Tool not found: missing");
  });

  it("wraps unexpected tool handler errors for safe serialization", async () => {
    const registry = new ToolRegistry();
    const policy = new RecordingPolicy();

    registry.register({
      name: toolName("failing-tool"),
      description: "Fails",
      inputSchema: jsonSchema,
      outputSchema: jsonSchema,
      requiredPermissions: [],
      execute() {
        throw new Error("raw-secret-value");
      }
    });

    const result = await registry.executeResult(toolName("failing-tool"), {}, { policy });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(serializeAppError(result.error)).toEqual({
        name: "AppError",
        code: "tool.execution_failed",
        message: "Tool execution failed: failing-tool",
        context: {
          toolName: "failing-tool"
        }
      });
    }
  });

  it("audits tool handler failures after allowed permission checks", async () => {
    const { audit, context } = createAuditContext();
    const registry = new ToolRegistry();
    const policy = new RecordingPolicy();

    registry.register({
      name: toolName("failing-audited-tool"),
      description: "Fails after permission",
      inputSchema: jsonSchema,
      outputSchema: jsonSchema,
      requiredPermissions: [],
      execute() {
        throw new Error("raw-secret-value");
      }
    });

    const result = await registry.executeResult(toolName("failing-audited-tool"), {}, { policy, audit: context });

    expect(result.ok).toBe(false);
    expect(audit.listEvents()).toEqual([
      expect.objectContaining({
        action: "tool.execute",
        decision: "pending",
        outcome: "requested",
        resource: expect.objectContaining({
          id: "failing-audited-tool"
        })
      }),
      expect.objectContaining({
        action: "tool.execute",
        decision: "allowed",
        outcome: "failed",
        resource: expect.objectContaining({
          id: "failing-audited-tool"
        })
      })
    ]);
    expect(JSON.stringify(audit.listEvents())).not.toContain("raw-secret-value");
  });
});
