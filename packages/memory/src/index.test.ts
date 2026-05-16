import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { InMemoryAuditSink } from "@dominic-nexus/audit";
import type { PermissionDecision, PermissionRequest, PolicyEngine } from "@dominic-nexus/permissions";
import {
  AppError,
  err,
  eventId,
  FixedClock,
  ok,
  SequentialIdGenerator,
  serializeAppError,
  sessionId
} from "@dominic-nexus/shared";
import {
  createDailyMemoryNoteRelativePath,
  createMemoryRoot,
  createMemoryWritePermissionRequest,
  dailyMemoryNoteDate,
  InMemoryStore,
  MarkdownMemoryStore,
  memoryNamespace,
  memoryRecordId,
  memoryRootPath,
  normalizeDailyMemoryNoteDate,
  normalizeMemoryNamespace,
  normalizeMemoryRecordId,
  normalizeMemoryRootPath,
  normalizeMemoryRecordWriteInput,
  parseMarkdownMemoryRecords,
  type MarkdownMemoryFileAccess,
  type MemoryFileAuthorizationRequest,
  type MemoryFileAuthorizer,
  type MemoryRoot
} from "./index.js";

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
    throw new Error("policy failed with secret memory content");
  }
}

function createAuditContext() {
  const audit = new InMemoryAuditSink();

  return {
    audit,
    context: {
      audit,
      clock: new FixedClock("2026-05-08T00:00:00.000Z"),
      idGenerator: new SequentialIdGenerator({ eventPrefix: "memory-audit" })
    }
  };
}

class FakeMarkdownMemoryFileAccess implements MarkdownMemoryFileAccess {
  readonly files = new Map<string, string>();
  readonly reads: string[] = [];
  readonly appends: Array<{ path: string; content: string }> = [];
  readonly replacements: Array<{ path: string; content: string }> = [];

  readText(path: string): string | undefined {
    this.reads.push(path);
    return this.files.get(path);
  }

  appendText(path: string, content: string): void {
    this.appends.push({ path, content });
    this.files.set(path, `${this.files.get(path) ?? ""}${content}`);
  }

  replaceText(path: string, content: string): void {
    this.replacements.push({ path, content });
    this.files.set(path, content);
  }
}

class ThrowingMarkdownMemoryFileAccess extends FakeMarkdownMemoryFileAccess {
  constructor(private readonly failOperation: "read" | "append") {
    super();
  }

  override readText(path: string): string | undefined {
    if (this.failOperation === "read") {
      throw new Error("read failed with secret memory content");
    }

    return super.readText(path);
  }

  override appendText(path: string, content: string): void {
    if (this.failOperation === "append") {
      throw new Error("append failed with secret memory content");
    }

    super.appendText(path, content);
  }
}

class RecordingMemoryFileAuthorizer {
  readonly requests: MemoryFileAuthorizationRequest[] = [];

  constructor(private readonly failure?: AppError) {}

  readonly authorize: MemoryFileAuthorizer = (request) => {
    this.requests.push(request);

    if (this.failure !== undefined) {
      return err(this.failure);
    }

    return ok({
      normalizedPath: `C:\\memory\\${request.relativePath}`,
      matchedRoot: "C:\\memory"
    });
  };
}

function createTestMemoryRoot(): MemoryRoot {
  const root = createMemoryRoot({
    rootPath: "C:\\memory"
  });

  if (!root.ok) {
    throw root.error;
  }

  return root.value;
}

function markdownMemoryRecordBlock(jsonContent: string): string {
  return [
    "<!-- dominic-nexus-memory-record:v1 -->",
    "```json",
    jsonContent,
    "```",
    "<!-- /dominic-nexus-memory-record -->"
  ].join("\n");
}

beforeEach(() => {
  vi.useFakeTimers();
  vi.setSystemTime(new Date("2026-01-02T03:04:05.000Z"));
});

afterEach(() => {
  vi.useRealTimers();
});

describe("InMemoryStore", () => {
  it("checks write/read permissions and searches records by namespace", async () => {
    const policy = new RecordingPolicy();
    const store = new InMemoryStore(policy);

    const first = await store.write({
      namespace: "notes",
      content: { text: "first" },
      metadata: { source: "test" }
    });
    await store.write({
      namespace: "other",
      content: { text: "second" }
    });

    const results = await store.search("notes");

    expect(first).toMatchObject({
      namespace: "notes",
      content: { text: "first" },
      metadata: { source: "test" },
      createdAt: "2026-01-02T03:04:05.000Z",
      updatedAt: "2026-01-02T03:04:05.000Z"
    });
    expect(first.id).toEqual(expect.any(String));
    expect(results).toEqual([first]);
    expect(policy.requests).toEqual([
      {
        action: "memory.write",
        reason: "Write memory record",
        resource: "notes",
        metadata: {
          namespace: "notes",
          durable: false,
          requiresFilesystemWrite: false
        }
      },
      {
        action: "memory.write",
        reason: "Write memory record",
        resource: "other",
        metadata: {
          namespace: "other",
          durable: false,
          requiresFilesystemWrite: false
        }
      },
      {
        action: "memory.read",
        reason: "Search memory records",
        resource: "notes",
        metadata: {
          namespace: "notes"
        }
      }
    ]);
  });

  it("audits allowed memory writes and reads without storing content", async () => {
    const { audit, context } = createAuditContext();
    const store = new InMemoryStore(new RecordingPolicy(), context);

    await store.write({
      namespace: "notes",
      content: {
        text: "secret memory content",
        token: "secret-token"
      },
      metadata: {
        password: "secret-password"
      }
    });
    await store.search("notes");

    const events = audit.listEvents();
    expect(events).toEqual([
      expect.objectContaining({
        action: "permission.decide",
        decision: "allowed",
        outcome: "succeeded"
      }),
      expect.objectContaining({
        action: "memory.write",
        decision: "allowed",
        outcome: "succeeded",
        resource: expect.objectContaining({
          id: "notes"
        }),
        metadata: expect.objectContaining({
          namespace: "notes"
        })
      }),
      expect.objectContaining({
        action: "permission.decide",
        decision: "allowed",
        outcome: "succeeded"
      }),
      expect.objectContaining({
        action: "memory.read",
        decision: "allowed",
        outcome: "succeeded",
        metadata: {
          namespace: "notes",
          resultCount: 1
        }
      })
    ]);
    expect(JSON.stringify(events)).not.toContain("secret memory content");
    expect(JSON.stringify(events)).not.toContain("secret-token");
    expect(JSON.stringify(events)).not.toContain("secret-password");
  });

  it("rejects invalid namespaces before checking permissions", async () => {
    const policy = new RecordingPolicy();
    const store = new InMemoryStore(policy);

    await expect(store.search("")).rejects.toMatchObject({
      code: "memory.invalid_model"
    });
    await expect(store.write({ namespace: "../sessions", content: "blocked" })).rejects.toMatchObject({
      code: "memory.invalid_model"
    });

    expect(policy.requests).toEqual([]);
  });

  it("audits missing namespace searches with zero results", async () => {
    const { audit, context } = createAuditContext();
    const store = new InMemoryStore(new RecordingPolicy(), context);

    await expect(store.search("missing")).resolves.toEqual([]);

    const readEvents = audit.listEvents().filter((event) => event.action === "memory.read");
    expect(readEvents).toEqual([
      expect.objectContaining({
        decision: "allowed",
        outcome: "succeeded",
        resource: expect.objectContaining({
          id: "missing"
        }),
        metadata: {
          namespace: "missing",
          resultCount: 0
        }
      })
    ]);
  });

  it("validates durable memory root and logical namespace helpers", () => {
    expect(createMemoryRoot({ rootPath: ".dominic-nexus/state/memory" })).toEqual({
      ok: true,
      value: {
        rootPath: ".dominic-nexus/state/memory",
        defaultNamespace: "default",
        layout: {
          format: "markdown",
          rootRecordFileName: "MEMORY.md",
          dailyNotesDirectory: "memory",
          dailyNoteFilePattern: "YYYY-MM-DD.md"
        },
        writeApproval: {
          requiredPermissionActions: ["memory.write", "filesystem.write"],
          auditAction: "memory.write",
          rootBounded: true,
          contentExcludedFromAudit: true,
          durableStoreWritesRequireFilesystemWrite: true
        }
      }
    });
    expect(normalizeMemoryNamespace("projects/dominic-nexus")).toEqual({
      ok: true,
      value: "projects/dominic-nexus"
    });
    expect(normalizeMemoryNamespace("../transcripts")).toMatchObject({
      ok: false,
      error: {
        code: "memory.invalid_model"
      }
    });
    expect(normalizeMemoryNamespace("projects\\dominic-nexus")).toMatchObject({
      ok: false,
      error: {
        code: "memory.invalid_model"
      }
    });
  });

  it("locks record id and root path validation boundaries", () => {
    expect(memoryRecordId("memory-abc_123")).toBe("memory-abc_123");
    expect(normalizeMemoryRecordId("record/../escape")).toMatchObject({
      ok: false,
      error: {
        code: "memory.invalid_model"
      }
    });
    expect(normalizeMemoryRecordId("record\\..\\escape")).toMatchObject({
      ok: false,
      error: {
        code: "memory.invalid_model"
      }
    });

    expect(memoryRootPath("/etc/passwd")).toBe("/etc/passwd");
    expect(normalizeMemoryRootPath("C:\\workspace\\memory")).toEqual({
      ok: true,
      value: "C:\\workspace\\memory"
    });
    expect(normalizeMemoryRootPath("valid\0path")).toMatchObject({
      ok: false,
      error: {
        code: "memory.invalid_model"
      }
    });
  });

  it("normalizes record writes without treating transcripts as memory records", () => {
    const normalized = normalizeMemoryRecordWriteInput({
      namespace: "notes",
      kind: "fact",
      content: {
        text: "Dominic Nexus is local-first"
      },
      metadata: {
        tag: "architecture"
      },
      provenance: {
        sessionId: sessionId("session-1"),
        transcriptEventId: eventId("event-1"),
        source: "agent"
      }
    });

    expect(normalized).toEqual({
      ok: true,
      value: {
        namespace: "notes",
        kind: "fact",
        content: {
          text: "Dominic Nexus is local-first"
        },
        metadata: {
          tag: "architecture"
        },
        provenance: {
          sessionId: "session-1",
          transcriptEventId: "event-1",
          source: "agent"
        }
      }
    });
    expect(normalizeMemoryRecordWriteInput({ namespace: "notes", content: new Date() })).toMatchObject({
      ok: false,
      error: {
        code: "memory.invalid_model"
      }
    });
  });

  it("describes durable memory writes as memory and filesystem approvals without content", () => {
    const request = createMemoryWritePermissionRequest(memoryNamespace("notes"), {
      durable: true,
      metadata: {
        operation: "append"
      }
    });

    expect(request).toEqual({
      action: "memory.write",
      reason: "Write memory record",
      resource: "notes",
      metadata: {
        operation: "append",
        namespace: "notes",
        durable: true,
        requiresFilesystemWrite: true
      }
    });
    expect(JSON.stringify(request)).not.toContain("content");
  });

  it("throws when memory.write permission is denied", async () => {
    const store = new InMemoryStore(new RecordingPolicy({ allowed: false, reason: "write denied" }));

    try {
      await store.write({ namespace: "notes", content: "blocked" });
      throw new Error("Expected memory write to fail");
    } catch (error) {
      expect(serializeAppError(error)).toEqual({
        name: "AppError",
        code: "memory.write_denied",
        message: "Memory write denied",
        context: {
          namespace: "notes"
        }
      });
    }
  });

  it("audits denied memory writes", async () => {
    const { audit, context } = createAuditContext();
    const store = new InMemoryStore(new RecordingPolicy({ allowed: false, reason: "write denied" }), context);

    await expect(store.write({ namespace: "notes", content: "blocked" })).rejects.toMatchObject({
      code: "memory.write_denied"
    });

    expect(audit.listEvents()).toEqual([
      expect.objectContaining({
        action: "permission.decide",
        decision: "denied",
        outcome: "denied"
      }),
      expect.objectContaining({
        action: "memory.write",
        decision: "denied",
        outcome: "denied",
        resource: expect.objectContaining({
          id: "notes"
        })
      })
    ]);
  });

  it("audits memory write permission check failures without storing content", async () => {
    const { audit, context } = createAuditContext();
    const store = new InMemoryStore(new ThrowingPolicy(), context);

    try {
      await store.write({
        namespace: "notes",
        content: {
          text: "secret memory content"
        }
      });
      throw new Error("Expected memory write permission check to fail");
    } catch (error) {
      expect(serializeAppError(error)).toEqual({
        name: "AppError",
        code: "unexpected",
        message: "Memory write permission check failed",
        context: {
          namespace: "notes"
        }
      });
    }

    const events = audit.listEvents();
    expect(events).toEqual([
      expect.objectContaining({
        action: "memory.write",
        decision: "not_applicable",
        outcome: "failed",
        resource: expect.objectContaining({
          id: "notes"
        }),
        metadata: {
          namespace: "notes",
          errorName: "Error"
        }
      })
    ]);
    expect(JSON.stringify(events)).not.toContain("secret memory content");
  });

  it("throws when memory.read permission is denied", async () => {
    const store = new InMemoryStore(new RecordingPolicy({ allowed: false, reason: "read denied" }));

    try {
      await store.search("notes");
      throw new Error("Expected memory read to fail");
    } catch (error) {
      expect(serializeAppError(error)).toEqual({
        name: "AppError",
        code: "memory.read_denied",
        message: "Memory read denied",
        context: {
          namespace: "notes"
        }
      });
    }
  });

  it("audits denied memory reads", async () => {
    const { audit, context } = createAuditContext();
    const store = new InMemoryStore(new RecordingPolicy({ allowed: false, reason: "read denied" }), context);

    await expect(store.search("notes")).rejects.toMatchObject({
      code: "memory.read_denied"
    });

    expect(audit.listEvents()).toEqual([
      expect.objectContaining({
        action: "permission.decide",
        decision: "denied",
        outcome: "denied"
      }),
      expect.objectContaining({
        action: "memory.read",
        decision: "denied",
        outcome: "denied",
        resource: expect.objectContaining({
          id: "notes"
        })
      })
    ]);
  });

  it("audits memory read permission check failures", async () => {
    const { audit, context } = createAuditContext();
    const store = new InMemoryStore(new ThrowingPolicy(), context);

    try {
      await store.search("notes");
      throw new Error("Expected memory read permission check to fail");
    } catch (error) {
      expect(serializeAppError(error)).toEqual({
        name: "AppError",
        code: "unexpected",
        message: "Memory read permission check failed",
        context: {
          namespace: "notes"
        }
      });
    }

    expect(audit.listEvents()).toEqual([
      expect.objectContaining({
        action: "memory.read",
        decision: "not_applicable",
        outcome: "failed",
        resource: expect.objectContaining({
          id: "notes"
        }),
        metadata: {
          namespace: "notes",
          errorName: "Error"
        }
      })
    ]);
  });
});

describe("parseMarkdownMemoryRecords", () => {
  it("rejects malformed managed Markdown record blocks", () => {
    expect(parseMarkdownMemoryRecords("<!-- dominic-nexus-memory-record:v1 -->\n")).toMatchObject({
      ok: false,
      error: {
        code: "memory.invalid_model",
        context: {
          recordIndex: 0
        }
      }
    });
    expect(
      parseMarkdownMemoryRecords(
        [
          "<!-- dominic-nexus-memory-record:v1 -->",
          "",
          "<!-- /dominic-nexus-memory-record -->"
        ].join("\n")
      )
    ).toMatchObject({
      ok: false,
      error: {
        code: "memory.invalid_model",
        context: {
          recordIndex: 0
        }
      }
    });
    expect(
      parseMarkdownMemoryRecords(
        [
          "<!-- dominic-nexus-memory-record:v1 -->",
          "```json",
          "{\"id\":\"memory-test\"}",
          "<!-- /dominic-nexus-memory-record -->"
        ].join("\n")
      )
    ).toMatchObject({
      ok: false,
      error: {
        code: "memory.invalid_model",
        context: {
          recordIndex: 0
        }
      }
    });
    expect(parseMarkdownMemoryRecords(markdownMemoryRecordBlock("{not-json"))).toMatchObject({
      ok: false,
      error: {
        code: "memory.invalid_model",
        context: {
          recordIndex: 0
        }
      }
    });
  });
});

describe("MarkdownMemoryStore", () => {
  it("creates deterministic daily note paths and rejects invalid dates", () => {
    const root = createTestMemoryRoot();

    expect(dailyMemoryNoteDate("2026-05-15")).toBe("2026-05-15");
    expect(normalizeDailyMemoryNoteDate("2026-02-30")).toMatchObject({
      ok: false,
      error: {
        code: "memory.invalid_model"
      }
    });
    expect(normalizeDailyMemoryNoteDate("2026/05/15")).toMatchObject({
      ok: false,
      error: {
        code: "memory.invalid_model"
      }
    });
    expect(createDailyMemoryNoteRelativePath(root, "2026-05-15")).toEqual({
      ok: true,
      value: "memory/2026-05-15.md"
    });
  });

  it("appends human-readable records to root MEMORY.md and searches by namespace", async () => {
    const policy = new RecordingPolicy();
    const access = new FakeMarkdownMemoryFileAccess();
    const authorizer = new RecordingMemoryFileAuthorizer();
    const store = new MarkdownMemoryStore({
      root: createTestMemoryRoot(),
      policy,
      fileAccess: access,
      authorizer: authorizer.authorize,
      clock: new FixedClock("2026-05-15T10:00:00.000Z"),
      createRecordId: () => memoryRecordId("memory-test-1")
    });

    const record = await store.write({
      namespace: "notes",
      kind: "fact",
      content: {
        text: "Dominic Nexus stores root memory in Markdown"
      },
      metadata: {
        tag: "architecture"
      },
      provenance: {
        sessionId: sessionId("session-1"),
        transcriptEventId: eventId("event-1"),
        source: "agent"
      }
    });
    const results = await store.search("notes");

    expect(record).toEqual({
      id: "memory-test-1",
      namespace: "notes",
      kind: "fact",
      content: {
        text: "Dominic Nexus stores root memory in Markdown"
      },
      metadata: {
        tag: "architecture"
      },
      provenance: {
        sessionId: sessionId("session-1"),
        transcriptEventId: eventId("event-1"),
        source: "agent"
      },
      createdAt: "2026-05-15T10:00:00.000Z",
      updatedAt: "2026-05-15T10:00:00.000Z"
    });
    expect(results).toEqual([record]);
    expect(access.files.get("C:\\memory\\MEMORY.md")).toContain("## Memory Record: memory-test-1");
    expect(access.files.get("C:\\memory\\MEMORY.md")).toContain("```json");
    expect(parseMarkdownMemoryRecords(access.files.get("C:\\memory\\MEMORY.md") ?? "")).toEqual({
      ok: true,
      value: [record]
    });
    expect(policy.requests).toEqual([
      {
        action: "memory.write",
        reason: "Write memory record",
        resource: "notes",
        metadata: {
          operation: "append",
          fileName: "MEMORY.md",
          namespace: "notes",
          durable: true,
          requiresFilesystemWrite: true
        }
      },
      {
        action: "memory.read",
        reason: "Search memory records",
        resource: "notes",
        metadata: {
          fileName: "MEMORY.md",
          namespace: "notes"
        }
      }
    ]);
    expect(authorizer.requests).toEqual([
      expect.objectContaining({
        operation: "append",
        relativePath: "MEMORY.md",
        metadata: {
          recordId: "memory-test-1",
          namespace: "notes",
          durable: true,
          fileName: "MEMORY.md",
          operation: "append"
        }
      }),
      expect.objectContaining({
        operation: "read",
        relativePath: "MEMORY.md",
        metadata: {
          namespace: "notes",
          durable: true,
          fileName: "MEMORY.md",
          operation: "read"
        }
      })
    ]);
  });

  it("returns an empty result for a missing root memory file", async () => {
    const { audit, context } = createAuditContext();
    const access = new FakeMarkdownMemoryFileAccess();
    const authorizer = new RecordingMemoryFileAuthorizer();
    const store = new MarkdownMemoryStore({
      root: createTestMemoryRoot(),
      policy: new RecordingPolicy(),
      fileAccess: access,
      authorizer: authorizer.authorize,
      auditContext: context
    });

    await expect(store.search("notes")).resolves.toEqual([]);

    expect(access.reads).toEqual(["C:\\memory\\MEMORY.md"]);
    expect(audit.listEvents()).toContainEqual(
      expect.objectContaining({
        action: "memory.read",
        decision: "allowed",
        outcome: "succeeded",
        metadata: {
          namespace: "notes",
          resultCount: 0,
          durable: true,
          fileName: "MEMORY.md",
          missingFile: true
        }
      })
    );
  });

  it("does not authorize or append when memory.write is denied", async () => {
    const { audit, context } = createAuditContext();
    const access = new FakeMarkdownMemoryFileAccess();
    const authorizer = new RecordingMemoryFileAuthorizer();
    const store = new MarkdownMemoryStore({
      root: createTestMemoryRoot(),
      policy: new RecordingPolicy({ allowed: false, reason: "write denied" }),
      fileAccess: access,
      authorizer: authorizer.authorize,
      auditContext: context
    });

    await expect(
      store.write({
        namespace: "notes",
        content: {
          text: "secret memory content",
          token: "secret-token"
        },
        metadata: {
          password: "secret-password"
        }
      })
    ).rejects.toMatchObject({
      code: "memory.write_denied"
    });

    expect(authorizer.requests).toEqual([]);
    expect(access.appends).toEqual([]);
    const events = audit.listEvents();
    expect(events).toContainEqual(
      expect.objectContaining({
        action: "memory.write",
        decision: "denied",
        outcome: "denied",
        metadata: expect.objectContaining({
          namespace: "notes",
          durable: true,
          fileName: "MEMORY.md"
        })
      })
    );
    expect(JSON.stringify(events)).not.toContain("secret memory content");
    expect(JSON.stringify(events)).not.toContain("secret-token");
    expect(JSON.stringify(events)).not.toContain("secret-password");
  });

  it("requires root-bounded file authorization before appending durable memory", async () => {
    const access = new FakeMarkdownMemoryFileAccess();
    const authorizer = new RecordingMemoryFileAuthorizer(
      new AppError({
        code: "filesystem.root_violation",
        message: "Filesystem path is outside approved roots",
        context: {
          path: "MEMORY.md"
        }
      })
    );
    const store = new MarkdownMemoryStore({
      root: createTestMemoryRoot(),
      policy: new RecordingPolicy(),
      fileAccess: access,
      authorizer: authorizer.authorize,
      clock: new FixedClock("2026-05-15T10:00:00.000Z"),
      createRecordId: () => memoryRecordId("memory-test-2")
    });

    await expect(store.write({ namespace: "notes", content: "blocked" })).rejects.toMatchObject({
      code: "filesystem.root_violation"
    });

    expect(authorizer.requests).toEqual([
      expect.objectContaining({
        operation: "append",
        relativePath: "MEMORY.md",
        metadata: expect.objectContaining({
          namespace: "notes",
          recordId: "memory-test-2"
        })
      })
    ]);
    expect(access.appends).toEqual([]);
  });

  it("audits append access failures without storing memory content", async () => {
    const { audit, context } = createAuditContext();
    const access = new ThrowingMarkdownMemoryFileAccess("append");
    const authorizer = new RecordingMemoryFileAuthorizer();
    const store = new MarkdownMemoryStore({
      root: createTestMemoryRoot(),
      policy: new RecordingPolicy(),
      fileAccess: access,
      authorizer: authorizer.authorize,
      auditContext: context,
      createRecordId: () => memoryRecordId("memory-test-append-failed")
    });

    await expect(
      store.write({
        namespace: "notes",
        content: {
          text: "secret memory content"
        }
      })
    ).rejects.toMatchObject({
      code: "unexpected"
    });

    const events = audit.listEvents();
    expect(events).toContainEqual(
      expect.objectContaining({
        action: "memory.write",
        decision: "allowed",
        outcome: "failed",
        metadata: {
          namespace: "notes",
          recordId: "memory-test-append-failed",
          durable: true,
          fileName: "MEMORY.md",
          operation: "append",
          errorName: "Error"
        }
      })
    );
    expect(JSON.stringify(events)).not.toContain("secret memory content");
  });

  it("audits read access failures without storing memory content", async () => {
    const { audit, context } = createAuditContext();
    const access = new ThrowingMarkdownMemoryFileAccess("read");
    const authorizer = new RecordingMemoryFileAuthorizer();
    const store = new MarkdownMemoryStore({
      root: createTestMemoryRoot(),
      policy: new RecordingPolicy(),
      fileAccess: access,
      authorizer: authorizer.authorize,
      auditContext: context
    });

    await expect(store.search("notes")).rejects.toMatchObject({
      code: "unexpected"
    });

    const events = audit.listEvents();
    expect(events).toContainEqual(
      expect.objectContaining({
        action: "memory.read",
        decision: "allowed",
        outcome: "failed",
        metadata: {
          namespace: "notes",
          fileName: "MEMORY.md",
          operation: "read",
          errorName: "Error"
        }
      })
    );
    expect(JSON.stringify(events)).not.toContain("secret memory content");
  });

  it("keeps allowed durable write and read audit metadata free of memory content", async () => {
    const { audit, context } = createAuditContext();
    const access = new FakeMarkdownMemoryFileAccess();
    const authorizer = new RecordingMemoryFileAuthorizer();
    const store = new MarkdownMemoryStore({
      root: createTestMemoryRoot(),
      policy: new RecordingPolicy(),
      fileAccess: access,
      authorizer: authorizer.authorize,
      auditContext: context,
      createRecordId: () => memoryRecordId("memory-test-3")
    });

    await store.write({
      namespace: "notes",
      content: {
        text: "secret memory content",
        token: "secret-token"
      },
      metadata: {
        password: "secret-password"
      }
    });
    await store.search("notes");

    const events = audit.listEvents();
    expect(events).toContainEqual(
      expect.objectContaining({
        action: "memory.write",
        decision: "allowed",
        outcome: "succeeded",
        metadata: {
          namespace: "notes",
          recordId: "memory-test-3",
          durable: true,
          fileName: "MEMORY.md",
          operation: "append"
        }
      })
    );
    expect(events).toContainEqual(
      expect.objectContaining({
        action: "memory.read",
        decision: "allowed",
        outcome: "succeeded",
        metadata: {
          namespace: "notes",
          resultCount: 1,
          durable: true,
          fileName: "MEMORY.md",
          missingFile: false
        }
      })
    );
    expect(JSON.stringify(events)).not.toContain("secret memory content");
    expect(JSON.stringify(events)).not.toContain("secret-token");
    expect(JSON.stringify(events)).not.toContain("secret-password");
  });

  it("appends daily notes under memory/YYYY-MM-DD.md and reads a single day", async () => {
    const policy = new RecordingPolicy();
    const access = new FakeMarkdownMemoryFileAccess();
    const authorizer = new RecordingMemoryFileAuthorizer();
    const store = new MarkdownMemoryStore({
      root: createTestMemoryRoot(),
      policy,
      fileAccess: access,
      authorizer: authorizer.authorize,
      clock: new FixedClock("2026-05-15T10:00:00.000Z"),
      createRecordId: () => memoryRecordId("memory-daily-1")
    });

    const record = await store.appendDailyNote({
      namespace: "notes",
      content: {
        text: "Daily memory note"
      }
    });
    const results = await store.readDailyNote("2026-05-15", "notes");

    expect(record).toMatchObject({
      id: "memory-daily-1",
      namespace: "notes",
      kind: "daily-note",
      content: {
        text: "Daily memory note"
      },
      createdAt: "2026-05-15T10:00:00.000Z",
      updatedAt: "2026-05-15T10:00:00.000Z"
    });
    expect(results).toEqual([record]);
    expect(access.files.get("C:\\memory\\memory/2026-05-15.md")).toContain("## Memory Record: memory-daily-1");
    expect(policy.requests).toEqual([
      {
        action: "memory.write",
        reason: "Write memory record",
        resource: "notes",
        metadata: {
          operation: "append",
          fileName: "memory/2026-05-15.md",
          dailyNoteDate: "2026-05-15",
          namespace: "notes",
          durable: true,
          requiresFilesystemWrite: true
        }
      },
      {
        action: "memory.read",
        reason: "Search daily memory notes",
        resource: "notes",
        metadata: {
          operation: "daily-note-search",
          startDate: "2026-05-15",
          endDate: "2026-05-15",
          limit: 50,
          namespace: "notes"
        }
      }
    ]);
    expect(authorizer.requests).toEqual([
      expect.objectContaining({
        operation: "append",
        relativePath: "memory/2026-05-15.md",
        metadata: {
          recordId: "memory-daily-1",
          namespace: "notes",
          durable: true,
          fileName: "memory/2026-05-15.md",
          dailyNoteDate: "2026-05-15",
          operation: "append"
        }
      }),
      expect.objectContaining({
        operation: "read",
        relativePath: "memory/2026-05-15.md",
        metadata: {
          namespace: "notes",
          durable: true,
          fileName: "memory/2026-05-15.md",
          dailyNoteDate: "2026-05-15",
          operation: "read"
        }
      })
    ]);
  });

  it("searches daily notes across multiple days with a result limit", async () => {
    const { audit, context } = createAuditContext();
    const access = new FakeMarkdownMemoryFileAccess();
    const authorizer = new RecordingMemoryFileAuthorizer();
    const ids = ["memory-daily-1", "memory-daily-2", "memory-daily-3"];
    const store = new MarkdownMemoryStore({
      root: createTestMemoryRoot(),
      policy: new RecordingPolicy(),
      fileAccess: access,
      authorizer: authorizer.authorize,
      auditContext: context,
      createRecordId: () => memoryRecordId(ids.shift() ?? "memory-daily-extra")
    });

    const first = await store.appendDailyNote({
      date: "2026-05-14",
      namespace: "notes",
      content: {
        text: "first"
      }
    });
    const second = await store.appendDailyNote({
      date: "2026-05-15",
      namespace: "other",
      content: {
        text: "ignored namespace"
      }
    });
    const third = await store.appendDailyNote({
      date: "2026-05-16",
      namespace: "notes",
      content: {
        text: "third"
      }
    });

    const limitedResults = await store.searchDailyNotes({
      namespace: "notes",
      startDate: "2026-05-14",
      endDate: "2026-05-16",
      limit: 1
    });
    const allResults = await store.searchDailyNotes({
      namespace: "notes",
      startDate: "2026-05-14",
      endDate: "2026-05-16",
      limit: 10
    });

    expect(second.namespace).toBe("other");
    expect(limitedResults).toEqual([first]);
    expect(allResults).toEqual([first, third]);
    expect(access.reads).toEqual([
      "C:\\memory\\memory/2026-05-14.md",
      "C:\\memory\\memory/2026-05-14.md",
      "C:\\memory\\memory/2026-05-15.md",
      "C:\\memory\\memory/2026-05-16.md"
    ]);
    expect(audit.listEvents()).toContainEqual(
      expect.objectContaining({
        action: "memory.read",
        decision: "allowed",
        outcome: "succeeded",
        metadata: {
          namespace: "notes",
          resultCount: 1,
          durable: true,
          operation: "daily-note-search",
          startDate: "2026-05-14",
          endDate: "2026-05-16",
          limit: 1,
          scannedFileCount: 1,
          missingFileCount: 0,
          truncated: true
        }
      })
    );
  });

  it("rejects invalid daily note dates before permission or file authorization", async () => {
    const policy = new RecordingPolicy();
    const access = new FakeMarkdownMemoryFileAccess();
    const authorizer = new RecordingMemoryFileAuthorizer();
    const store = new MarkdownMemoryStore({
      root: createTestMemoryRoot(),
      policy,
      fileAccess: access,
      authorizer: authorizer.authorize
    });

    await expect(
      store.appendDailyNote({
        date: "../2026-05-15",
        namespace: "notes",
        content: "blocked"
      })
    ).rejects.toMatchObject({
      code: "memory.invalid_model"
    });
    await expect(
      store.searchDailyNotes({
        namespace: "notes",
        startDate: "2026-05-15",
        endDate: "2026-05-45"
      })
    ).rejects.toMatchObject({
      code: "memory.invalid_model"
    });

    expect(policy.requests).toEqual([]);
    expect(authorizer.requests).toEqual([]);
    expect(access.appends).toEqual([]);
    expect(access.reads).toEqual([]);
  });

  it("keeps daily note audit metadata free of memory content and secret-like values", async () => {
    const { audit, context } = createAuditContext();
    const access = new FakeMarkdownMemoryFileAccess();
    const authorizer = new RecordingMemoryFileAuthorizer();
    const store = new MarkdownMemoryStore({
      root: createTestMemoryRoot(),
      policy: new RecordingPolicy(),
      fileAccess: access,
      authorizer: authorizer.authorize,
      auditContext: context,
      createRecordId: () => memoryRecordId("memory-daily-secret-safe")
    });

    await store.appendDailyNote({
      date: "2026-05-15",
      namespace: "notes",
      content: {
        text: "secret memory content",
        token: "secret-token"
      },
      metadata: {
        password: "secret-password"
      }
    });
    await store.searchDailyNotes({
      namespace: "notes",
      startDate: "2026-05-15",
      endDate: "2026-05-15",
      limit: 5
    });

    const events = audit.listEvents();
    expect(events).toContainEqual(
      expect.objectContaining({
        action: "memory.write",
        decision: "allowed",
        outcome: "succeeded",
        metadata: {
          namespace: "notes",
          recordId: "memory-daily-secret-safe",
          durable: true,
          fileName: "memory/2026-05-15.md",
          dailyNoteDate: "2026-05-15",
          operation: "append"
        }
      })
    );
    expect(JSON.stringify(events)).not.toContain("secret memory content");
    expect(JSON.stringify(events)).not.toContain("secret-token");
    expect(JSON.stringify(events)).not.toContain("secret-password");
  });
});
