import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, expect, it, vi } from "vitest";
import { appendAuditEvent, InMemoryAuditSink } from "@dominic-nexus/audit";
import type { AppConfig } from "@dominic-nexus/config";
import type { Logger } from "@dominic-nexus/logging";
import { InMemoryStore, memoryNamespace, memoryRecordId, type MemoryStore } from "@dominic-nexus/memory";
import { AllowAllDevelopmentPolicy, DefaultDenyPolicy } from "@dominic-nexus/permissions";
import { MockProvider, ProviderRegistry, type ChatRequest, type ChatResponse, type ModelProvider } from "@dominic-nexus/providers";
import { EnvSecretStore, envSecret, type SecretStore } from "@dominic-nexus/secrets";
import {
  agentId,
  AppError,
  channelId,
  err,
  eventId,
  FixedClock,
  ok,
  providerName,
  SequentialIdGenerator,
  sessionId,
  toolName,
  type DomainEvent,
  type EventId,
  type Clock,
  type ISODateTimeString,
  type Result,
  type RuntimeUtilities
} from "@dominic-nexus/shared";
import { FilesystemRootPolicy, ToolRegistry } from "@dominic-nexus/tools";
import {
  AgentRunner,
  createChannelSessionRoutingKey,
  createAgentSession,
  createCliSessionRoutingKey,
  createRuntimeContext,
  createRuntimeDomainEvent,
  DirectorySessionStore,
  DirectoryTranscriptStore,
  emitRuntimeDomainEvent,
  LocalRuntimeEventBus,
  RecordingRuntimeEventSubscriber,
  parseSessionRoutingKey,
  startRuntime,
  type AgentRunnerTimers,
  type AppendTranscriptEventInput,
  type PersistedSession,
  type RuntimeEventBus,
  type SessionStore,
  type SessionStoreAccess,
  type TranscriptEvent,
  type TranscriptReadResult,
  type TranscriptStore,
  type TranscriptStoreAccess
} from "./index.js";

const config: AppConfig = {
  appName: "Test Nexus",
  environment: "test",
  logLevel: "info",
  stateDirectory: "C:\\workspace\\state"
};

const logger: Logger = {
  debug: vi.fn(),
  info: vi.fn(),
  warn: vi.fn(),
  error: vi.fn()
};

function createLogger(): Logger {
  return {
    debug: vi.fn(),
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn()
  };
}

async function flushMicrotasks(iterations = 50): Promise<void> {
  for (let index = 0; index < iterations; index += 1) {
    await Promise.resolve();
  }
}

class MutableClock implements Clock {
  constructor(private current: ISODateTimeString) {}

  set(value: ISODateTimeString): void {
    this.current = value;
  }

  now(): Date {
    return new Date(this.current);
  }

  nowIso(): ISODateTimeString {
    return this.current;
  }
}

function createWindowsFilesystemRootPolicy(root = "C:\\workspace"): FilesystemRootPolicy {
  return new FilesystemRootPolicy({
    roots: [root],
    cwd: root,
    platform: "win32",
    access: {
      realpath() {
        throw new Error("ENOENT");
      }
    }
  });
}

function createStoredSessionJson(options: {
  id: string;
  agentId?: string;
  sessionStartedAt?: string;
  lastInteractionAt?: string | null;
  updatedAt?: string;
  attributes?: Record<string, unknown>;
}): string {
  return `${JSON.stringify({
    id: options.id,
    agentId: options.agentId ?? "agent-default",
    metadata: {
      sessionStartedAt: options.sessionStartedAt ?? "2026-05-10T00:00:00.000Z",
      lastInteractionAt: options.lastInteractionAt ?? null,
      updatedAt: options.updatedAt ?? "2026-05-10T00:00:00.000Z",
      attributes: options.attributes ?? {}
    }
  })}\n`;
}

function createRecordingSessionStoreAccess(
  initialFiles: Record<string, string> = {},
  options: {
    initialDirectories?: string[];
    failOnWrite?: boolean;
    failOnRename?: boolean;
  } = {}
) {
  const files = new Map(Object.entries(initialFiles));
  const directories = new Set<string>(options.initialDirectories ?? []);
  const operations: string[] = [];
  const access: SessionStoreAccess = {
    async mkdir(dirPath) {
      operations.push(`mkdir:${dirPath}`);
      directories.add(dirPath);
    },
    async readDirectory(dirPath) {
      operations.push(`readDirectory:${dirPath}`);
      if (!directories.has(dirPath) && ![...files.keys()].some((filePath) => path.dirname(filePath) === dirPath)) {
        const error = new Error("ENOENT") as Error & { code: string };
        error.code = "ENOENT";
        throw error;
      }

      return [...files.keys()]
        .filter((filePath) => path.dirname(filePath) === dirPath)
        .map((filePath) => path.basename(filePath));
    },
    async readFile(filePath) {
      operations.push(`read:${filePath}`);
      const content = files.get(filePath);
      if (content === undefined) {
        const error = new Error("ENOENT") as Error & { code: string };
        error.code = "ENOENT";
        throw error;
      }

      return content;
    },
    async rename(fromPath, toPath) {
      operations.push(`rename:${fromPath}->${toPath}`);
      if (options.failOnRename === true) {
        throw new Error("ERENAME");
      }

      const content = files.get(fromPath);
      if (content === undefined) {
        throw new Error("ENOENT");
      }

      files.set(toPath, content);
      files.delete(fromPath);
    },
    async writeFile(filePath, content) {
      operations.push(`write:${filePath}`);
      if (options.failOnWrite === true) {
        throw new Error("EWRITE");
      }

      files.set(filePath, content);
    }
  };

  return {
    access,
    files,
    operations
  };
}

function createRecordingTranscriptStoreAccess(
  initialFiles: Record<string, string> = {},
  options: {
    failOnAppend?: boolean;
    failOnAppendAt?: number;
    failOnRead?: boolean;
    appendDelayMs?: number;
  } = {}
) {
  const files = new Map(Object.entries(initialFiles));
  const operations: string[] = [];
  let activeAppends = 0;
  let maxActiveAppends = 0;
  let appendAttempts = 0;
  const access: TranscriptStoreAccess = {
    async appendFile(filePath, content) {
      appendAttempts += 1;
      operations.push(`append:start:${filePath}`);
      if (options.failOnAppend === true || options.failOnAppendAt === appendAttempts) {
        throw new Error("EAPPEND");
      }

      activeAppends += 1;
      maxActiveAppends = Math.max(maxActiveAppends, activeAppends);
      if (options.appendDelayMs !== undefined) {
        await new Promise((resolve) => setTimeout(resolve, options.appendDelayMs));
      }

      files.set(filePath, `${files.get(filePath) ?? ""}${content}`);
      activeAppends -= 1;
      operations.push(`append:end:${filePath}`);
    },
    async mkdir(dirPath) {
      operations.push(`mkdir:${dirPath}`);
    },
    async readFile(filePath) {
      operations.push(`read:${filePath}`);
      if (options.failOnRead === true) {
        throw new Error("EREAD");
      }

      const content = files.get(filePath);
      if (content === undefined) {
        const error = new Error("ENOENT") as Error & { code: string };
        error.code = "ENOENT";
        throw error;
      }

      return content;
    }
  };

  return {
    access,
    files,
    operations,
    getMaxActiveAppends() {
      return maxActiveAppends;
    }
  };
}

class RecordingTranscriptStore implements TranscriptStore {
  readonly events: TranscriptEvent[] = [];
  readonly operations: string[] = [];
  private nextEventNumber = 1;

  constructor(private readonly session: ReturnType<typeof sessionId>) {}

  async append<TType extends TranscriptEvent["type"]>(
    session: ReturnType<typeof sessionId>,
    input: AppendTranscriptEventInput<TType>
  ): Promise<Result<TranscriptEvent<TType>>> {
    this.operations.push(`append:start:${input.type}`);
    await Promise.resolve();

    const event = {
      type: input.type,
      eventId: eventId(`runner-event-${this.nextEventNumber}`),
      sessionId: session,
      timestamp: "2026-05-10T00:00:00.000Z",
      payload: input.payload
    } as TranscriptEvent<TType>;
    this.nextEventNumber += 1;
    this.events.push(event);
    this.operations.push(`append:end:${input.type}`);

    return ok(event);
  }

  async read(session: ReturnType<typeof sessionId>): Promise<Result<TranscriptReadResult>> {
    this.operations.push("read");
    return ok({
      sessionId: session,
      events: [...this.events],
      malformedLines: []
    });
  }
}

class FailingReadTranscriptStore extends RecordingTranscriptStore {
  override async read(): Promise<Result<TranscriptReadResult>> {
    this.operations.push("read");
    return err(
      new AppError({
        code: "transcript.read_failed",
        message: "Transcript read failed in test"
      })
    );
  }
}

class FailingAppendTranscriptStore extends RecordingTranscriptStore {
  private appendCount = 0;

  constructor(
    session: ReturnType<typeof sessionId>,
    private readonly failOnAppendNumber: number
  ) {
    super(session);
  }

  override async append<TType extends TranscriptEvent["type"]>(
    session: ReturnType<typeof sessionId>,
    input: AppendTranscriptEventInput<TType>
  ): Promise<Result<TranscriptEvent<TType>>> {
    this.appendCount += 1;
    this.operations.push(`append:start:${input.type}`);
    await Promise.resolve();

    if (this.appendCount === this.failOnAppendNumber) {
      this.operations.push(`append:failed:${input.type}`);
      return err(
        new AppError({
          code: "transcript.write_failed",
          message: `Transcript append failed in test: ${input.type}`,
          context: {
            eventType: input.type
          }
        })
      );
    }

    const result = await super.append(session, input);
    this.operations.splice(this.operations.lastIndexOf(`append:start:${input.type}`), 1);
    return result;
  }
}

class RecordingProvider implements ModelProvider {
  readonly capabilities = {
    chat: true,
    modelListing: false
  };
  readonly requests: ChatRequest[] = [];

  constructor(
    private readonly operations: string[],
    readonly name = providerName("mock"),
    private readonly response: ChatResponse = {
      message: {
        role: "assistant",
        content: "assistant reply"
      }
    }
  ) {}

  async chat(request: ChatRequest): Promise<ChatResponse> {
    this.operations.push("provider:chat");
    this.requests.push(request);
    return this.response;
  }
}

class ThrowingProvider implements ModelProvider {
  readonly name = providerName("mock");
  readonly capabilities = {
    chat: true,
    modelListing: false
  };

  constructor(private readonly error: Error, private readonly operations: string[]) {}

  async chat(): Promise<ChatResponse> {
    this.operations.push("provider:chat");
    throw this.error;
  }
}

class DeferredProvider implements ModelProvider {
  readonly name = providerName("mock");
  readonly capabilities = {
    chat: true,
    modelListing: false
  };
  readonly requests: ChatRequest[] = [];
  readonly promise: Promise<ChatResponse>;
  private resolveResponse!: (response: ChatResponse) => void;
  private rejectResponse!: (error: unknown) => void;

  constructor(private readonly operations: string[]) {
    this.promise = new Promise<ChatResponse>((resolve, reject) => {
      this.resolveResponse = resolve;
      this.rejectResponse = reject;
    });
  }

  async chat(request: ChatRequest): Promise<ChatResponse> {
    this.operations.push("provider:chat");
    this.requests.push(request);
    return this.promise;
  }

  resolve(response: ChatResponse = { message: { role: "assistant", content: "late reply" } }): void {
    this.resolveResponse(response);
  }

  reject(error: unknown): void {
    this.rejectResponse(error);
  }
}

class SequencedDeferredProvider implements ModelProvider {
  readonly name = providerName("mock");
  readonly capabilities = {
    chat: true,
    modelListing: false
  };
  readonly requests: ChatRequest[] = [];
  private readonly pending: Array<{
    label: string;
    resolve(response: ChatResponse): void;
    reject(error: unknown): void;
  }> = [];

  constructor(private readonly operations: string[]) {}

  async chat(request: ChatRequest): Promise<ChatResponse> {
    const lastMessage = request.messages.at(-1);
    const label = lastMessage?.content ?? "unknown";
    this.operations.push(`provider:chat:${label}`);
    this.requests.push(request);

    return new Promise<ChatResponse>((resolve, reject) => {
      this.pending.push({ label, resolve, reject });
    });
  }

  resolveNext(content = "queued reply"): void {
    const next = this.pending.shift();
    if (next === undefined) {
      throw new Error("No pending provider request to resolve");
    }

    next.resolve({
      message: {
        role: "assistant",
        content
      }
    });
  }

  rejectNext(error: unknown): void {
    const next = this.pending.shift();
    if (next === undefined) {
      throw new Error("No pending provider request to reject");
    }

    next.reject(error);
  }

  resolveByLabel(label: string, content = "queued reply"): void {
    const index = this.pending.findIndex((request) => request.label === label);
    if (index < 0) {
      throw new Error(`No pending provider request to resolve for ${label}`);
    }

    const [next] = this.pending.splice(index, 1);
    next?.resolve({
      message: {
        role: "assistant",
        content
      }
    });
  }
}

class RecordingSessionStore implements SessionStore {
  readonly operations: string[] = [];

  constructor(private readonly result: Result<PersistedSession>) {}

  async create(): Promise<Result<PersistedSession>> {
    throw new Error("not used");
  }

  async list(): Promise<Result<PersistedSession[]>> {
    throw new Error("not used");
  }

  async load(): Promise<Result<PersistedSession>> {
    throw new Error("not used");
  }

  async update(id: ReturnType<typeof sessionId>): Promise<Result<PersistedSession>> {
    this.operations.push(`session:update:${id}`);
    return this.result;
  }
}

function createRunnerSession(options: {
  audit?: InMemoryAuditSink;
  clock?: Clock;
  eventBus?: RuntimeEventBus;
  idGenerator?: SequentialIdGenerator;
  transcripts: TranscriptStore;
  provider?: ModelProvider;
  logger?: Logger;
  sessions?: SessionStore;
  policy?: AllowAllDevelopmentPolicy | DefaultDenyPolicy;
}) {
  const providers = new ProviderRegistry();
  if (options.provider !== undefined) {
    providers.register(options.provider);
  }

  const runtime = createRuntimeContext({
    config,
    logger: options.logger ?? logger,
    policy: options.policy ?? new AllowAllDevelopmentPolicy(),
    ...(options.audit !== undefined ? { audit: options.audit } : {}),
    ...(options.clock !== undefined ? { clock: options.clock } : {}),
    ...(options.eventBus !== undefined ? { eventBus: options.eventBus } : {}),
    ...(options.idGenerator !== undefined ? { idGenerator: options.idGenerator } : {}),
    providers,
    transcripts: options.transcripts,
    sessions:
      options.sessions ??
      new RecordingSessionStore(
        err(
          new AppError({
            code: "session.not_found",
            message: "Session not persisted in test"
          })
        )
      )
  });

  return {
    runtime,
    session: {
      id: sessionId("session-runner"),
      agentId: agentId("agent-default"),
      runtime,
      metadata: {
        sessionStartedAt: "2026-05-10T00:00:00.000Z",
        lastInteractionAt: null,
        updatedAt: "2026-05-10T00:00:00.000Z",
        attributes: {}
      }
    }
  };
}

describe("createRuntimeContext", () => {
  it("creates registries and registers the built-in tools", async () => {
    const policy = new AllowAllDevelopmentPolicy();
    const runtime = createRuntimeContext({ config, logger, policy });

    expect(runtime.config).toBe(config);
    expect(runtime.logger).toBe(logger);
    expect(runtime.policy).toBe(policy);
    expect(runtime.audit).toBeInstanceOf(InMemoryAuditSink);
    expect(runtime.tools).toBeInstanceOf(ToolRegistry);
    expect(runtime.providers).toBeInstanceOf(ProviderRegistry);
    expect(runtime.memory).toBeInstanceOf(InMemoryStore);
    expect(runtime.secrets).toBeInstanceOf(EnvSecretStore);
    expect(runtime.transcripts).toBeInstanceOf(DirectoryTranscriptStore);
    expect(runtime.eventBus).toBeInstanceOf(LocalRuntimeEventBus);
    expect(runtime.filesystem).toBeInstanceOf(FilesystemRootPolicy);
    expect(runtime.utilities.clock).toBe(runtime.clock);
    expect(runtime.utilities.idGenerator).toBe(runtime.idGenerator);
    expect(runtime.clock.now()).toBeInstanceOf(Date);
    expect(runtime.idGenerator.createSessionId()).toMatch(/^session-/);
    await expect(runtime.tools.execute(toolName("echo"), "hello", { policy })).resolves.toBe("hello");
    expect(runtime.tools.get(toolName("filesystem.read_file"))).toEqual(
      expect.objectContaining({
        name: "filesystem.read_file",
        requiredPermissions: ["filesystem.read"]
      })
    );
    expect(runtime.tools.get(toolName("filesystem.write_file"))).toEqual(
      expect.objectContaining({
        name: "filesystem.write_file",
        requiredPermissions: ["filesystem.write"]
      })
    );
    expect(runtime.tools.get(toolName("web.fetch"))).toEqual(
      expect.objectContaining({
        name: "web.fetch",
        requiredPermissions: ["network.request"]
      })
    );
    expect(runtime.tools.get(toolName("web.search"))).toBeUndefined();
    expect(runtime.tools.get(toolName("shell.execute"))).toBeUndefined();
  });

  it("creates a filesystem policy with the current working directory as the default root", () => {
    const runtime = createRuntimeContext({ config, logger, policy: new AllowAllDevelopmentPolicy() });

    expect(runtime.filesystem.roots).toEqual([path.resolve(process.cwd())]);
  });

  it("accepts explicit filesystem roots", () => {
    const runtime = createRuntimeContext({
      config,
      logger,
      policy: new AllowAllDevelopmentPolicy(),
      filesystemRoots: ["C:\\workspace"]
    });

    expect(runtime.filesystem.roots).toEqual(["C:\\workspace"]);
  });

  it("preserves caller-provided dependency instances", () => {
    const policy = new AllowAllDevelopmentPolicy();
    const audit = new InMemoryAuditSink();
    const eventBus = new LocalRuntimeEventBus(logger);
    const tools = new ToolRegistry();
    const providers = new ProviderRegistry();
    const memory: MemoryStore = {
      async write(record) {
        return {
          ...record,
          id: memoryRecordId("memory-test"),
          namespace: memoryNamespace(record.namespace),
          createdAt: "2026-05-08T00:00:00.000Z",
          updatedAt: "2026-05-08T00:00:00.000Z"
        };
      },
      async search() {
        return [];
      }
    };
    const secrets: SecretStore = {
      async read() {
        return "provided-secret";
      }
    };
    const sessions: SessionStore = {
      async create() {
        throw new Error("not used");
      },
      async list() {
        return {
          ok: true,
          value: []
        };
      },
      async load() {
        throw new Error("not used");
      },
      async update() {
        throw new Error("not used");
      }
    };
    const transcripts: TranscriptStore = {
      async append() {
        throw new Error("not used");
      },
      async read() {
        return {
          ok: true,
          value: {
            sessionId: sessionId("session-1"),
            events: [],
            malformedLines: []
          }
        };
      }
    };
    const filesystem = new FilesystemRootPolicy({
      roots: ["C:\\workspace"]
    });
    const clock = new FixedClock("2026-05-08T00:00:00.000Z");
    const idGenerator = new SequentialIdGenerator();
    const utilities = {
      clock,
      idGenerator
    };

    const runtime = createRuntimeContext({
      config,
      logger,
      policy,
      audit,
      eventBus,
      tools,
      providers,
      memory,
      secrets,
      sessions,
      transcripts,
      filesystem,
      utilities
    });

    expect(runtime.audit).toBe(audit);
    expect(runtime.eventBus).toBe(eventBus);
    expect(runtime.tools).toBe(tools);
    expect(runtime.tools.get(toolName("echo"))).toBeUndefined();
    expect(runtime.tools.get(toolName("filesystem.read_file"))).toBeUndefined();
    expect(runtime.tools.get(toolName("filesystem.write_file"))).toBeUndefined();
    expect(runtime.tools.get(toolName("web.fetch"))).toBeUndefined();
    expect(runtime.tools.get(toolName("web.search"))).toBeUndefined();
    expect(runtime.tools.get(toolName("shell.execute"))).toBeUndefined();
    expect(runtime.providers).toBe(providers);
    expect(runtime.memory).toBe(memory);
    expect(runtime.secrets).toBe(secrets);
    expect(runtime.sessions).toBe(sessions);
    expect(runtime.transcripts).toBe(transcripts);
    expect(runtime.filesystem).toBe(filesystem);
    expect(runtime.utilities).toBe(utilities);
    expect(runtime.clock).toBe(clock);
    expect(runtime.idGenerator).toBe(idGenerator);
  });

  it("preserves utility extension fields when overriding one utility member", () => {
    const originalClock = new FixedClock("2026-05-08T00:00:00.000Z");
    const overrideClock = new FixedClock("2026-05-09T00:00:00.000Z");
    const idGenerator = new SequentialIdGenerator();
    const customUtility = {
      label: "future-utility"
    };
    const utilities = {
      clock: originalClock,
      idGenerator,
      customUtility
    } as RuntimeUtilities & {
      customUtility: { label: string };
    };

    const runtime = createRuntimeContext({
      config,
      logger,
      policy: new AllowAllDevelopmentPolicy(),
      utilities,
      clock: overrideClock
    });

    expect(runtime.utilities).not.toBe(utilities);
    expect(runtime.utilities.clock).toBe(overrideClock);
    expect(runtime.utilities.idGenerator).toBe(idGenerator);
    expect((runtime.utilities as RuntimeUtilities & { customUtility: { label: string } }).customUtility).toBe(
      customUtility
    );
    expect(runtime.clock).toBe(runtime.utilities.clock);
    expect(runtime.idGenerator).toBe(runtime.utilities.idGenerator);
  });

  it("uses explicit secret env for the default secret store", async () => {
    const runtime = createRuntimeContext({
      config,
      logger,
      policy: new AllowAllDevelopmentPolicy(),
      secretEnv: {
        DOMINIC_NEXUS_TEST_SECRET: "secret-value"
      }
    });

    await expect(runtime.secrets.read(envSecret("DOMINIC_NEXUS_TEST_SECRET"))).resolves.toBe("secret-value");
  });

  it("does not read ambient environment from the default secret store", async () => {
    const runtime = createRuntimeContext({
      config,
      logger,
      policy: new AllowAllDevelopmentPolicy()
    });

    // createRuntimeContext injects an explicit empty env object when secretEnv is omitted.
    await expect(runtime.secrets.read(envSecret("PATH"))).resolves.toBeUndefined();
  });

  it("accepts an injected deterministic audit sink", async () => {
    const audit = new InMemoryAuditSink();
    const runtime = createRuntimeContext({
      config,
      logger,
      policy: new AllowAllDevelopmentPolicy(),
      audit,
      clock: new FixedClock("2026-05-08T00:00:00.000Z"),
      idGenerator: new SequentialIdGenerator({ eventPrefix: "audit-event" })
    });

    await appendAuditEvent(runtime, {
      sourcePackage: "@dominic-nexus/core",
      action: "permission.decide",
      decision: "allowed",
      resource: {
        type: "permission",
        id: "provider.call"
      },
      outcome: "succeeded"
    });

    expect(audit.listEvents()).toEqual([
      {
        eventId: eventId("audit-event-1"),
        timestamp: "2026-05-08T00:00:00.000Z",
        sourcePackage: "@dominic-nexus/core",
        action: "permission.decide",
        decision: "allowed",
        resource: {
          type: "permission",
          id: "provider.call"
        },
        outcome: "succeeded"
      }
    ]);
  });

  it("uses config.stateDirectory for the default durable session store", async () => {
    const stateRoot = await mkdtemp(path.join(tmpdir(), "dominic-nexus-session-store-"));

    try {
      const runtime = createRuntimeContext({
        config: {
          ...config,
          stateDirectory: path.join(stateRoot, "state")
        },
        logger,
        policy: new AllowAllDevelopmentPolicy(),
        filesystemRoots: [stateRoot],
        clock: new FixedClock("2026-05-10T00:00:00.000Z"),
        idGenerator: new SequentialIdGenerator()
      });

      const created = await runtime.sessions.create();

      expect(created.ok).toBe(true);
      expect(await runtime.sessions.load(sessionId("session-1"))).toEqual(created);
    } finally {
      await rm(stateRoot, {
        force: true,
        recursive: true
      });
    }
  });
});

describe("createAgentSession", () => {
  it("creates a deterministic session id from injected runtime utilities and attaches runtime", () => {
    const idGenerator = new SequentialIdGenerator();
    const runtime = createRuntimeContext({
      config,
      logger,
      policy: new AllowAllDevelopmentPolicy(),
      idGenerator
    });

    const session = createAgentSession(runtime);

    expect(session).toEqual({
      id: sessionId("session-1"),
      agentId: agentId("agent-default"),
      runtime,
      metadata: {
        sessionStartedAt: expect.any(String),
        lastInteractionAt: null,
        updatedAt: expect.any(String),
        attributes: {}
      }
    });
  });
});

describe("DirectorySessionStore", () => {
  it("lists an empty session directory as an empty result", async () => {
    const sessionsDirectory = "C:\\workspace\\state\\sessions";
    const { access } = createRecordingSessionStoreAccess({}, {
      initialDirectories: [sessionsDirectory]
    });
    const store = new DirectorySessionStore({
      stateDirectory: "C:\\workspace\\state",
      filesystem: createWindowsFilesystemRootPolicy(),
      policy: new AllowAllDevelopmentPolicy(),
      audit: new InMemoryAuditSink(),
      clock: new FixedClock("2026-05-10T00:00:00.000Z"),
      idGenerator: new SequentialIdGenerator(),
      access
    });

    await expect(store.list()).resolves.toEqual({
      ok: true,
      value: []
    });
  });

  it("creates, lists, loads, and updates durable session metadata", async () => {
    const clock = new MutableClock("2026-05-10T00:00:00.000Z");
    const idGenerator = new SequentialIdGenerator();
    const { access, files } = createRecordingSessionStoreAccess();
    const store = new DirectorySessionStore({
      stateDirectory: "C:\\workspace\\state",
      filesystem: createWindowsFilesystemRootPolicy(),
      policy: new AllowAllDevelopmentPolicy(),
      audit: new InMemoryAuditSink(),
      clock,
      idGenerator,
      access
    });

    const created = await store.create({
      attributes: {
        title: "First session"
      }
    });

    expect(created).toEqual({
      ok: true,
      value: {
        id: sessionId("session-1"),
        agentId: agentId("agent-default"),
        metadata: {
          sessionStartedAt: "2026-05-10T00:00:00.000Z",
          lastInteractionAt: null,
          updatedAt: "2026-05-10T00:00:00.000Z",
          attributes: {
            title: "First session"
          }
        }
      }
    });
    expect(files.has("C:\\workspace\\state\\sessions\\session-1.json")).toBe(true);

    clock.set("2026-05-10T00:01:00.000Z");
    const updated = await store.update(sessionId("session-1"), {
      attributes: {
        channel: "cli"
      },
      touchInteraction: true
    });

    expect(updated).toEqual({
      ok: true,
      value: {
        id: sessionId("session-1"),
        agentId: agentId("agent-default"),
        metadata: {
          sessionStartedAt: "2026-05-10T00:00:00.000Z",
          lastInteractionAt: "2026-05-10T00:01:00.000Z",
          updatedAt: "2026-05-10T00:01:00.000Z",
          attributes: {
            title: "First session",
            channel: "cli"
          }
        }
      }
    });

    await expect(store.load(sessionId("session-1"))).resolves.toEqual(updated);
    await expect(store.list()).resolves.toEqual({
      ok: true,
      value: [updated.ok ? updated.value : expect.anything()]
    });
  });

  it("creates a session with a custom agent id", async () => {
    const { access } = createRecordingSessionStoreAccess();
    const store = new DirectorySessionStore({
      stateDirectory: "C:\\workspace\\state",
      filesystem: createWindowsFilesystemRootPolicy(),
      policy: new AllowAllDevelopmentPolicy(),
      audit: new InMemoryAuditSink(),
      clock: new FixedClock("2026-05-10T00:00:00.000Z"),
      idGenerator: new SequentialIdGenerator(),
      access
    });

    const created = await store.create({
      agentId: agentId("custom-agent")
    });

    expect(created.ok).toBe(true);
    if (created.ok) {
      expect(created.value.agentId).toBe(agentId("custom-agent"));
    }
  });

  it("lists multiple sessions by updatedAt descending and skips corrupt files", async () => {
    const sessionsDirectory = "C:\\workspace\\state\\sessions";
    const { access } = createRecordingSessionStoreAccess({
      "C:\\workspace\\state\\sessions\\session-1.json": createStoredSessionJson({
        id: "session-1",
        updatedAt: "2026-05-10T00:01:00.000Z"
      }),
      "C:\\workspace\\state\\sessions\\session-2.json": createStoredSessionJson({
        id: "session-2",
        updatedAt: "2026-05-10T00:03:00.000Z"
      }),
      "C:\\workspace\\state\\sessions\\session-3.json": "{malformed-json",
      "C:\\workspace\\state\\sessions\\session-4.json": createStoredSessionJson({
        id: "session-4",
        updatedAt: "2026-05-10T00:02:00.000Z"
      })
    }, {
      initialDirectories: [sessionsDirectory]
    });
    const store = new DirectorySessionStore({
      stateDirectory: "C:\\workspace\\state",
      filesystem: createWindowsFilesystemRootPolicy(),
      policy: new AllowAllDevelopmentPolicy(),
      audit: new InMemoryAuditSink(),
      clock: new FixedClock("2026-05-10T00:00:00.000Z"),
      idGenerator: new SequentialIdGenerator(),
      access
    });

    const listed = await store.list();

    expect(listed.ok).toBe(true);
    if (listed.ok) {
      expect(listed.value.map((session) => session.id)).toEqual([
        sessionId("session-2"),
        sessionId("session-4"),
        sessionId("session-1")
      ]);
    }
  });

  it("loads missing and malformed sessions as typed session errors", async () => {
    const { access } = createRecordingSessionStoreAccess({
      "C:\\workspace\\state\\sessions\\malformed.json": "{malformed-json",
      "C:\\workspace\\state\\sessions\\session-1.json": createStoredSessionJson({
        id: "session-2"
      })
    });
    const store = new DirectorySessionStore({
      stateDirectory: "C:\\workspace\\state",
      filesystem: createWindowsFilesystemRootPolicy(),
      policy: new AllowAllDevelopmentPolicy(),
      audit: new InMemoryAuditSink(),
      clock: new FixedClock("2026-05-10T00:00:00.000Z"),
      idGenerator: new SequentialIdGenerator(),
      access
    });

    const missing = await store.load(sessionId("missing"));
    expect(missing.ok).toBe(false);
    if (!missing.ok) {
      expect(missing.error.code).toBe("session.not_found");
    }

    const malformed = await store.load(sessionId("malformed"));
    expect(malformed.ok).toBe(false);
    if (!malformed.ok) {
      expect(malformed.error.code).toBe("session.invalid");
      expect(malformed.error.message).toBe("Session metadata file contains malformed JSON");
    }

    const mismatched = await store.load(sessionId("session-1"));
    expect(mismatched.ok).toBe(false);
    if (!mismatched.ok) {
      expect(mismatched.error.code).toBe("session.invalid");
      expect(mismatched.error.message).toBe("Session metadata id does not match the requested session");
    }
  });

  it("does not extend interaction freshness for background metadata updates", async () => {
    const clock = new MutableClock("2026-05-10T00:00:00.000Z");
    const { access } = createRecordingSessionStoreAccess();
    const store = new DirectorySessionStore({
      stateDirectory: "C:\\workspace\\state",
      filesystem: createWindowsFilesystemRootPolicy(),
      policy: new AllowAllDevelopmentPolicy(),
      audit: new InMemoryAuditSink(),
      clock,
      idGenerator: new SequentialIdGenerator(),
      access
    });

    await store.create();
    clock.set("2026-05-10T00:01:00.000Z");
    await store.update(sessionId("session-1"), {
      touchInteraction: true
    });
    clock.set("2026-05-10T00:02:00.000Z");
    const background = await store.update(sessionId("session-1"), {
      attributes: {
        backgroundRefresh: true
      },
      touchInteraction: false
    });

    expect(background.ok).toBe(true);
    if (background.ok) {
      expect(background.value.metadata.sessionStartedAt).toBe("2026-05-10T00:00:00.000Z");
      expect(background.value.metadata.lastInteractionAt).toBe("2026-05-10T00:01:00.000Z");
      expect(background.value.metadata.updatedAt).toBe("2026-05-10T00:02:00.000Z");
    }
  });

  it("preserves lastInteractionAt when touchInteraction is omitted and overwrites attribute keys", async () => {
    const clock = new MutableClock("2026-05-10T00:00:00.000Z");
    const { access } = createRecordingSessionStoreAccess();
    const store = new DirectorySessionStore({
      stateDirectory: "C:\\workspace\\state",
      filesystem: createWindowsFilesystemRootPolicy(),
      policy: new AllowAllDevelopmentPolicy(),
      audit: new InMemoryAuditSink(),
      clock,
      idGenerator: new SequentialIdGenerator(),
      access
    });

    await store.create({
      attributes: {
        title: "Old title",
        source: "cli"
      }
    });
    clock.set("2026-05-10T00:01:00.000Z");
    await store.update(sessionId("session-1"), {
      touchInteraction: true
    });
    clock.set("2026-05-10T00:02:00.000Z");

    const updated = await store.update(sessionId("session-1"), {
      attributes: {
        title: "New title"
      }
    });

    expect(updated.ok).toBe(true);
    if (updated.ok) {
      expect(updated.value.metadata.lastInteractionAt).toBe("2026-05-10T00:01:00.000Z");
      expect(updated.value.metadata.updatedAt).toBe("2026-05-10T00:02:00.000Z");
      expect(updated.value.metadata.attributes).toEqual({
        title: "New title",
        source: "cli"
      });
    }
  });

  it("requires filesystem.write permission before mutating session metadata", async () => {
    const audit = new InMemoryAuditSink();
    const { access, operations } = createRecordingSessionStoreAccess();
    const store = new DirectorySessionStore({
      stateDirectory: "C:\\workspace\\state",
      filesystem: createWindowsFilesystemRootPolicy(),
      policy: new DefaultDenyPolicy(),
      audit,
      clock: new FixedClock("2026-05-10T00:00:00.000Z"),
      idGenerator: new SequentialIdGenerator(),
      access
    });

    const result = await store.create();

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe("filesystem.permission_denied");
    }
    expect(operations).toEqual([]);
    expect(audit.listEvents()).toEqual([
      expect.objectContaining({
        action: "permission.decide",
        decision: "denied",
        resource: expect.objectContaining({
          id: "filesystem.write"
        })
      })
    ]);
  });

  it("returns session.write_failed when an authorized session metadata write fails", async () => {
    const { access: writeFailureAccess } = createRecordingSessionStoreAccess({}, {
      failOnWrite: true
    });
    const writeFailureStore = new DirectorySessionStore({
      stateDirectory: "C:\\workspace\\state",
      filesystem: createWindowsFilesystemRootPolicy(),
      policy: new AllowAllDevelopmentPolicy(),
      audit: new InMemoryAuditSink(),
      clock: new FixedClock("2026-05-10T00:00:00.000Z"),
      idGenerator: new SequentialIdGenerator(),
      access: writeFailureAccess
    });

    const writeFailure = await writeFailureStore.create();
    expect(writeFailure.ok).toBe(false);
    if (!writeFailure.ok) {
      expect(writeFailure.error.code).toBe("session.write_failed");
    }

    const { access: renameFailureAccess } = createRecordingSessionStoreAccess({}, {
      failOnRename: true
    });
    const renameFailureStore = new DirectorySessionStore({
      stateDirectory: "C:\\workspace\\state",
      filesystem: createWindowsFilesystemRootPolicy(),
      policy: new AllowAllDevelopmentPolicy(),
      audit: new InMemoryAuditSink(),
      clock: new FixedClock("2026-05-10T00:00:00.000Z"),
      idGenerator: new SequentialIdGenerator(),
      access: renameFailureAccess
    });

    const renameFailure = await renameFailureStore.create();
    expect(renameFailure.ok).toBe(false);
    if (!renameFailure.ok) {
      expect(renameFailure.error.code).toBe("session.write_failed");
    }
  });

  it("rejects session state paths outside configured filesystem roots", async () => {
    const { access, operations } = createRecordingSessionStoreAccess();
    const store = new DirectorySessionStore({
      stateDirectory: "C:\\outside\\state",
      filesystem: createWindowsFilesystemRootPolicy("C:\\workspace"),
      policy: new AllowAllDevelopmentPolicy(),
      audit: new InMemoryAuditSink(),
      clock: new FixedClock("2026-05-10T00:00:00.000Z"),
      idGenerator: new SequentialIdGenerator(),
      access
    });

    const result = await store.create();

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe("filesystem.root_violation");
    }
    expect(operations).toEqual([]);
  });

  it("rejects unsafe session ids before resolving file paths", async () => {
    const { access, operations } = createRecordingSessionStoreAccess();
    const store = new DirectorySessionStore({
      stateDirectory: "C:\\workspace\\state",
      filesystem: createWindowsFilesystemRootPolicy(),
      policy: new AllowAllDevelopmentPolicy(),
      audit: new InMemoryAuditSink(),
      clock: new FixedClock("2026-05-10T00:00:00.000Z"),
      idGenerator: new SequentialIdGenerator(),
      access
    });

    const result = await store.load(sessionId("..\\secret"));

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe("session.invalid");
    }
    expect(operations).toEqual([]);
  });
});

describe("DirectoryTranscriptStore", () => {
  it("appends and reads transcript JSONL events", async () => {
    const { access, files } = createRecordingTranscriptStoreAccess();
    const store = new DirectoryTranscriptStore({
      stateDirectory: "C:\\workspace\\state",
      filesystem: createWindowsFilesystemRootPolicy(),
      policy: new AllowAllDevelopmentPolicy(),
      audit: new InMemoryAuditSink(),
      clock: new FixedClock("2026-05-10T00:00:00.000Z"),
      idGenerator: new SequentialIdGenerator(),
      access
    });

    const user = await store.append(sessionId("session-1"), {
      type: "user",
      payload: {
        content: "hello"
      }
    });
    const assistant = await store.append(sessionId("session-1"), {
      type: "assistant",
      payload: {
        content: "hi"
      }
    });
    const tool = await store.append(sessionId("session-1"), {
      type: "tool",
      payload: {
        toolName: toolName("echo"),
        phase: "succeeded",
        output: "hi"
      }
    });
    const lifecycle = await store.append(sessionId("session-1"), {
      type: "lifecycle",
      payload: {
        name: "turn.started"
      }
    });
    const error = await store.append(sessionId("session-1"), {
      type: "error",
      payload: {
        errorName: "AppError",
        message: "safe failure",
        code: "unexpected"
      }
    });

    expect(user.ok).toBe(true);
    expect(assistant.ok).toBe(true);
    expect(tool.ok).toBe(true);
    expect(lifecycle.ok).toBe(true);
    expect(error.ok).toBe(true);
    expect(files.get("C:\\workspace\\state\\transcripts\\session-1.jsonl")?.split("\n").filter(Boolean)).toHaveLength(5);

    const read = await store.read(sessionId("session-1"));

    expect(read.ok).toBe(true);
    if (read.ok) {
      expect(read.value.malformedLines).toEqual([]);
      expect(read.value.events.map((event) => event.type)).toEqual(["user", "assistant", "tool", "lifecycle", "error"]);
      expect(read.value.events.map((event) => event.eventId)).toEqual([
        eventId("event-1"),
        eventId("event-3"),
        eventId("event-5"),
        eventId("event-7"),
        eventId("event-9")
      ]);
    }
  });

  it("reads a missing transcript as an empty transcript", async () => {
    const { access } = createRecordingTranscriptStoreAccess();
    const store = new DirectoryTranscriptStore({
      stateDirectory: "C:\\workspace\\state",
      filesystem: createWindowsFilesystemRootPolicy(),
      policy: new AllowAllDevelopmentPolicy(),
      audit: new InMemoryAuditSink(),
      clock: new FixedClock("2026-05-10T00:00:00.000Z"),
      idGenerator: new SequentialIdGenerator(),
      access
    });

    await expect(store.read(sessionId("missing"))).resolves.toEqual({
      ok: true,
      value: {
        sessionId: sessionId("missing"),
        events: [],
        malformedLines: []
      }
    });
  });

  it("waits for a pending append before reading the same session transcript", async () => {
    const { access, operations } = createRecordingTranscriptStoreAccess({}, {
      appendDelayMs: 5
    });
    const store = new DirectoryTranscriptStore({
      stateDirectory: "C:\\workspace\\state",
      filesystem: createWindowsFilesystemRootPolicy(),
      policy: new AllowAllDevelopmentPolicy(),
      audit: new InMemoryAuditSink(),
      clock: new FixedClock("2026-05-10T00:00:00.000Z"),
      idGenerator: new SequentialIdGenerator(),
      access
    });

    const append = store.append(sessionId("session-1"), {
      type: "user",
      payload: {
        content: "queued"
      }
    });
    const read = await store.read(sessionId("session-1"));
    const appended = await append;

    expect(appended.ok).toBe(true);
    expect(read.ok).toBe(true);
    if (read.ok) {
      expect(read.value.events).toHaveLength(1);
      expect(read.value.events[0]).toEqual(
        expect.objectContaining({
          type: "user",
          payload: {
            content: "queued"
          }
        })
      );
    }
    expect(operations.indexOf("append:end:C:\\workspace\\state\\transcripts\\session-1.jsonl")).toBeLessThan(
      operations.indexOf("read:C:\\workspace\\state\\transcripts\\session-1.jsonl")
    );
  });

  it("recovers valid events while reporting malformed transcript lines", async () => {
    const validLine = JSON.stringify({
      type: "user",
      eventId: "event-1",
      sessionId: "session-1",
      timestamp: "2026-05-10T00:00:00.000Z",
      payload: {
        content: "hello"
      }
    });
    const wrongShapeLine = JSON.stringify({
      type: "assistant",
      eventId: "event-2",
      sessionId: "session-1",
      timestamp: "2026-05-10T00:00:00.000Z",
      payload: {
        metadata: {}
      }
    });
    const wrongSessionLine = JSON.stringify({
      type: "lifecycle",
      eventId: "event-3",
      sessionId: "session-2",
      timestamp: "2026-05-10T00:00:00.000Z",
      payload: {
        name: "turn.started"
      }
    });
    const { access } = createRecordingTranscriptStoreAccess({
      "C:\\workspace\\state\\transcripts\\session-1.jsonl": `${validLine}\n{not-json\n${wrongShapeLine}\n${wrongSessionLine}\n`
    });
    const store = new DirectoryTranscriptStore({
      stateDirectory: "C:\\workspace\\state",
      filesystem: createWindowsFilesystemRootPolicy(),
      policy: new AllowAllDevelopmentPolicy(),
      audit: new InMemoryAuditSink(),
      clock: new FixedClock("2026-05-10T00:00:00.000Z"),
      idGenerator: new SequentialIdGenerator(),
      access
    });

    const read = await store.read(sessionId("session-1"));

    expect(read.ok).toBe(true);
    if (read.ok) {
      expect(read.value.events).toEqual([
        {
          type: "user",
          eventId: eventId("event-1"),
          sessionId: sessionId("session-1"),
          timestamp: "2026-05-10T00:00:00.000Z",
          payload: {
            content: "hello"
          }
        }
      ]);
      expect(read.value.malformedLines).toEqual([
        expect.objectContaining({
          lineNumber: 2,
          reason: "Malformed JSON",
          errorName: "SyntaxError",
          length: "{not-json".length
        }),
        expect.objectContaining({
          lineNumber: 3,
          reason: "Transcript message content must be a string",
          errorName: "AppError",
          length: wrongShapeLine.length
        }),
        expect.objectContaining({
          lineNumber: 4,
          reason: "Transcript event sessionId does not match the requested session",
          errorName: "AppError",
          length: wrongSessionLine.length
        })
      ]);
    }
  });

  it("requires filesystem.write permission before appending transcript events", async () => {
    const audit = new InMemoryAuditSink();
    const { access, operations } = createRecordingTranscriptStoreAccess();
    const store = new DirectoryTranscriptStore({
      stateDirectory: "C:\\workspace\\state",
      filesystem: createWindowsFilesystemRootPolicy(),
      policy: new DefaultDenyPolicy(),
      audit,
      clock: new FixedClock("2026-05-10T00:00:00.000Z"),
      idGenerator: new SequentialIdGenerator(),
      access
    });

    const result = await store.append(sessionId("session-1"), {
      type: "user",
      payload: {
        content: "hello"
      }
    });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe("filesystem.permission_denied");
    }
    expect(operations).toEqual([]);
    expect(audit.listEvents()).toEqual([
      expect.objectContaining({
        action: "permission.decide",
        decision: "denied",
        resource: expect.objectContaining({
          id: "filesystem.write"
        })
      })
    ]);
  });

  it("audits successful append filesystem.write permission decisions", async () => {
    const audit = new InMemoryAuditSink();
    const { access } = createRecordingTranscriptStoreAccess();
    const store = new DirectoryTranscriptStore({
      stateDirectory: "C:\\workspace\\state",
      filesystem: createWindowsFilesystemRootPolicy(),
      policy: new AllowAllDevelopmentPolicy(),
      audit,
      clock: new FixedClock("2026-05-10T00:00:00.000Z"),
      idGenerator: new SequentialIdGenerator(),
      access
    });

    const result = await store.append(sessionId("session-1"), {
      type: "user",
      payload: {
        content: "hello"
      }
    });

    expect(result.ok).toBe(true);
    expect(audit.listEvents()).toEqual([
      expect.objectContaining({
        action: "permission.decide",
        decision: "allowed",
        resource: expect.objectContaining({
          id: "filesystem.write"
        }),
        metadata: expect.objectContaining({
          requestMetadata: expect.objectContaining({
            eventType: "user",
            operation: "write"
          })
        })
      })
    ]);
  });

  it("serializes concurrent appends for the same session", async () => {
    const { access, files, getMaxActiveAppends } = createRecordingTranscriptStoreAccess({}, {
      appendDelayMs: 5
    });
    const store = new DirectoryTranscriptStore({
      stateDirectory: "C:\\workspace\\state",
      filesystem: createWindowsFilesystemRootPolicy(),
      policy: new AllowAllDevelopmentPolicy(),
      audit: new InMemoryAuditSink(),
      clock: new FixedClock("2026-05-10T00:00:00.000Z"),
      idGenerator: new SequentialIdGenerator(),
      access
    });

    const [first, second] = await Promise.all([
      store.append(sessionId("session-1"), {
        type: "user",
        payload: {
          content: "first"
        }
      }),
      store.append(sessionId("session-1"), {
        type: "assistant",
        payload: {
          content: "second"
        }
      })
    ]);

    expect(first.ok).toBe(true);
    expect(second.ok).toBe(true);
    expect(getMaxActiveAppends()).toBe(1);

    const rawLines = files.get("C:\\workspace\\state\\transcripts\\session-1.jsonl")?.split("\n").filter(Boolean) ?? [];
    expect(rawLines.map((line) => JSON.parse(line) as { type: string; payload: { content: string } })).toEqual([
      expect.objectContaining({
        type: "user",
        payload: {
          content: "first"
        }
      }),
      expect.objectContaining({
        type: "assistant",
        payload: {
          content: "second"
        }
      })
    ]);
  });

  it("returns transcript.write_failed when an authorized append fails", async () => {
    const { access } = createRecordingTranscriptStoreAccess({}, {
      failOnAppend: true
    });
    const store = new DirectoryTranscriptStore({
      stateDirectory: "C:\\workspace\\state",
      filesystem: createWindowsFilesystemRootPolicy(),
      policy: new AllowAllDevelopmentPolicy(),
      audit: new InMemoryAuditSink(),
      clock: new FixedClock("2026-05-10T00:00:00.000Z"),
      idGenerator: new SequentialIdGenerator(),
      access
    });

    const result = await store.append(sessionId("session-1"), {
      type: "user",
      payload: {
        content: "hello"
      }
    });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe("transcript.write_failed");
    }
  });

  it("continues reading and appending after a queued append fails", async () => {
    const { access } = createRecordingTranscriptStoreAccess({}, {
      failOnAppendAt: 2
    });
    const store = new DirectoryTranscriptStore({
      stateDirectory: "C:\\workspace\\state",
      filesystem: createWindowsFilesystemRootPolicy(),
      policy: new AllowAllDevelopmentPolicy(),
      audit: new InMemoryAuditSink(),
      clock: new FixedClock("2026-05-10T00:00:00.000Z"),
      idGenerator: new SequentialIdGenerator(),
      access
    });

    const first = await store.append(sessionId("session-1"), {
      type: "user",
      payload: {
        content: "first"
      }
    });
    const failed = await store.append(sessionId("session-1"), {
      type: "assistant",
      payload: {
        content: "failed"
      }
    });
    const third = await store.append(sessionId("session-1"), {
      type: "assistant",
      payload: {
        content: "third"
      }
    });
    const read = await store.read(sessionId("session-1"));

    expect(first.ok).toBe(true);
    expect(failed.ok).toBe(false);
    if (!failed.ok) {
      expect(failed.error.code).toBe("transcript.write_failed");
    }
    expect(third.ok).toBe(true);
    expect(read.ok).toBe(true);
    if (read.ok) {
      expect(read.value.events.map((event) => event.payload)).toEqual([
        {
          content: "first"
        },
        {
          content: "third"
        }
      ]);
    }
  });

  it("returns transcript.read_failed when a transcript file read fails", async () => {
    const { access } = createRecordingTranscriptStoreAccess({
      "C:\\workspace\\state\\transcripts\\session-1.jsonl": ""
    }, {
      failOnRead: true
    });
    const store = new DirectoryTranscriptStore({
      stateDirectory: "C:\\workspace\\state",
      filesystem: createWindowsFilesystemRootPolicy(),
      policy: new AllowAllDevelopmentPolicy(),
      audit: new InMemoryAuditSink(),
      clock: new FixedClock("2026-05-10T00:00:00.000Z"),
      idGenerator: new SequentialIdGenerator(),
      access
    });

    const result = await store.read(sessionId("session-1"));

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe("transcript.read_failed");
    }
  });

  it("rejects transcript reads outside configured filesystem roots", async () => {
    const { access, operations } = createRecordingTranscriptStoreAccess();
    const store = new DirectoryTranscriptStore({
      stateDirectory: "C:\\outside\\state",
      filesystem: createWindowsFilesystemRootPolicy("C:\\workspace"),
      policy: new AllowAllDevelopmentPolicy(),
      audit: new InMemoryAuditSink(),
      clock: new FixedClock("2026-05-10T00:00:00.000Z"),
      idGenerator: new SequentialIdGenerator(),
      access
    });

    const result = await store.read(sessionId("session-1"));

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe("filesystem.root_violation");
    }
    expect(operations).toEqual([]);
  });

  it("rejects unsafe transcript session ids before resolving file paths", async () => {
    const { access, operations } = createRecordingTranscriptStoreAccess();
    const store = new DirectoryTranscriptStore({
      stateDirectory: "C:\\workspace\\state",
      filesystem: createWindowsFilesystemRootPolicy(),
      policy: new AllowAllDevelopmentPolicy(),
      audit: new InMemoryAuditSink(),
      clock: new FixedClock("2026-05-10T00:00:00.000Z"),
      idGenerator: new SequentialIdGenerator(),
      access
    });

    const result = await store.read(sessionId("..\\secret"));

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe("transcript.invalid");
    }
    expect(operations).toEqual([]);
  });
});

describe("session routing", () => {
  it("creates deterministic JSON-safe CLI routing keys", () => {
    const first = createCliSessionRoutingKey({
      sessionId: sessionId("session-route")
    });
    const second = createCliSessionRoutingKey({
      sessionId: " session-route "
    });

    expect(first.ok).toBe(true);
    expect(second.ok).toBe(true);
    if (first.ok && second.ok) {
      expect(first.value).toBe(second.value);
      expect(parseSessionRoutingKey(first.value)).toEqual(
        ok({
          version: 1,
          kind: "cli",
          sessionId: "session-route"
        })
      );
    }
  });

  it("creates deterministic JSON-safe channel routing keys without auth semantics", () => {
    const first = createChannelSessionRoutingKey({
      channelId: channelId("channel-local"),
      accountId: " account-a ",
      roomId: " room-a ",
      threadId: " thread-a ",
      senderId: " sender-a "
    });
    const second = createChannelSessionRoutingKey({
      channelId: "channel-local",
      accountId: "account-a",
      roomId: "room-a",
      threadId: "thread-a",
      senderId: "sender-a",
      scope: "thread"
    });

    expect(first.ok).toBe(true);
    expect(second.ok).toBe(true);
    if (first.ok && second.ok) {
      expect(first.value).toBe(second.value);
      expect(parseSessionRoutingKey(first.value)).toEqual(
        ok({
          version: 1,
          kind: "channel",
          scope: "thread",
          channelId: "channel-local",
          accountId: "account-a",
          roomId: "room-a",
          threadId: "thread-a",
          senderId: "sender-a"
        })
      );
    }
  });

  it("rejects empty routing key components", () => {
    const result = createChannelSessionRoutingKey({
      channelId: "local",
      threadId: "   "
    });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe("session.invalid");
      expect(result.error.context).toEqual({
        field: "threadId"
      });
    }
  });
});

describe("AgentRunner", () => {
  it("awaits lifecycle and user transcript appends before provider call, then appends assistant and touches session", async () => {
    const audit = new InMemoryAuditSink();
    const eventSubscriber = new RecordingRuntimeEventSubscriber();
    const eventBus = new LocalRuntimeEventBus(logger);
    eventBus.subscribe(eventSubscriber.handle);
    const transcripts = new RecordingTranscriptStore(sessionId("session-runner"));
    const provider = new RecordingProvider(transcripts.operations, providerName("mock"), {
      message: {
        role: "assistant",
        content: "hello back",
        metadata: {
          providerRequestId: "request-1"
        }
      }
    });
    const sessions = new RecordingSessionStore(
      ok({
        id: sessionId("session-runner"),
        agentId: agentId("agent-default"),
        metadata: {
          sessionStartedAt: "2026-05-10T00:00:00.000Z",
          lastInteractionAt: "2026-05-10T00:01:00.000Z",
          updatedAt: "2026-05-10T00:01:00.000Z",
          attributes: {}
        }
      })
    );
    const { session } = createRunnerSession({
      transcripts,
      provider,
      sessions,
      audit,
      eventBus,
      clock: new FixedClock("2026-05-10T00:00:00.000Z"),
      idGenerator: new SequentialIdGenerator()
    });

    const result = await new AgentRunner().runTurn(session, {
      content: " hello ",
      metadata: {
        channel: "test"
      },
      model: "mock/default"
    });

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value).toEqual({
        content: "hello back",
        message: {
          role: "assistant",
          content: "hello back",
          metadata: {
            providerRequestId: "request-1"
          }
        },
        providerName: providerName("mock"),
        model: "mock/default",
        transcriptEvents: {
          lifecycle: eventId("runner-event-1"),
          user: eventId("runner-event-2"),
          assistant: eventId("runner-event-3")
        },
        sessionUpdate: {
          persisted: true,
          metadata: {
            sessionStartedAt: "2026-05-10T00:00:00.000Z",
            lastInteractionAt: "2026-05-10T00:01:00.000Z",
            updatedAt: "2026-05-10T00:01:00.000Z",
            attributes: {}
          }
        }
      });
    }
    expect(transcripts.operations).toEqual([
      "append:start:lifecycle",
      "append:end:lifecycle",
      "append:start:user",
      "append:end:user",
      "read",
      "provider:chat",
      "append:start:assistant",
      "append:end:assistant"
    ]);
    expect(provider.requests).toEqual([
      {
        messages: [
          {
            role: "user",
            content: "hello",
            metadata: {
              channel: "test"
            }
          }
        ],
        model: "mock/default",
        metadata: {
          channel: "test",
          sessionId: "session-runner"
        }
      }
    ]);
    expect(sessions.operations).toEqual(["session:update:session-runner"]);
    expect(session.metadata.lastInteractionAt).toBe("2026-05-10T00:01:00.000Z");
    expect(transcripts.events.map((event) => event.type)).toEqual(["lifecycle", "user", "assistant"]);
    expect(eventSubscriber.listEvents()).toEqual([
      expect.objectContaining({
        type: "provider.call_requested",
        eventId: eventId("event-2"),
        timestamp: "2026-05-10T00:00:00.000Z",
        sourcePackage: "@dominic-nexus/core",
        sessionId: sessionId("session-runner"),
        payload: {
          providerName: providerName("mock"),
          model: "mock/default",
          messageCount: 1
        }
      }),
      expect.objectContaining({
        type: "provider.call_succeeded",
        eventId: eventId("event-6"),
        timestamp: "2026-05-10T00:00:00.000Z",
        sourcePackage: "@dominic-nexus/core",
        sessionId: sessionId("session-runner"),
        payload: {
          providerName: providerName("mock"),
          model: "mock/default",
          messageCount: 1
        }
      }),
      expect.objectContaining({
        type: "session.updated",
        eventId: eventId("event-7"),
        timestamp: "2026-05-10T00:00:00.000Z",
        sourcePackage: "@dominic-nexus/core",
        sessionId: sessionId("session-runner"),
        payload: {
          reason: "turn.completed"
        }
      })
    ]);
    expect(audit.listEvents()).toEqual([
      expect.objectContaining({
        sourcePackage: "@dominic-nexus/core",
        action: "provider.call_requested",
        decision: "pending",
        outcome: "requested",
        sessionId: sessionId("session-runner"),
        metadata: expect.objectContaining({
          messageCount: 1,
          model: "mock/default"
        })
      }),
      expect.objectContaining({
        sourcePackage: "@dominic-nexus/permissions",
        action: "permission.decide",
        decision: "allowed",
        outcome: "succeeded",
        resource: expect.objectContaining({
          id: "provider.call"
        })
      }),
      expect.objectContaining({
        sourcePackage: "@dominic-nexus/providers",
        action: "provider.call",
        decision: "allowed",
        outcome: "succeeded",
        resource: expect.objectContaining({
          id: "mock"
        }),
        metadata: expect.objectContaining({
          messageCount: 1,
          model: "mock/default"
        })
      }),
      expect.objectContaining({
        sourcePackage: "@dominic-nexus/core",
        action: "provider.call_succeeded",
        decision: "allowed",
        outcome: "succeeded",
        sessionId: sessionId("session-runner"),
        metadata: expect.objectContaining({
          messageCount: 1,
          model: "mock/default"
        })
      })
    ]);
  });

  it("queues same-session turns and runs them in order", async () => {
    const transcripts = new RecordingTranscriptStore(sessionId("session-runner"));
    const provider = new SequencedDeferredProvider(transcripts.operations);
    const { session } = createRunnerSession({
      transcripts,
      provider
    });
    const runner = new AgentRunner();

    const firstPromise = runner.runTurn(session, {
      content: "first"
    });
    await flushMicrotasks();
    expect(provider.requests).toHaveLength(1);

    const secondPromise = runner.runTurn(session, {
      content: "second"
    });
    await flushMicrotasks();
    expect(provider.requests).toHaveLength(1);

    provider.resolveNext("first reply");
    const first = await firstPromise;
    await flushMicrotasks();
    expect(first.ok).toBe(true);
    expect(provider.requests).toHaveLength(2);

    provider.resolveNext("second reply");
    const second = await secondPromise;

    expect(second.ok).toBe(true);
    if (second.ok) {
      expect(second.value.content).toBe("second reply");
    }
    expect(transcripts.operations).toEqual([
      "append:start:lifecycle",
      "append:end:lifecycle",
      "append:start:user",
      "append:end:user",
      "read",
      "provider:chat:first",
      "append:start:assistant",
      "append:end:assistant",
      "append:start:lifecycle",
      "append:end:lifecycle",
      "append:start:user",
      "append:end:user",
      "read",
      "provider:chat:second",
      "append:start:assistant",
      "append:end:assistant"
    ]);
    expect(provider.requests[1]?.messages.map((message) => message.content)).toEqual([
      "first",
      "first reply",
      "second"
    ]);
  });

  it("does not block separate sessions behind an active turn", async () => {
    const transcripts = new RecordingTranscriptStore(sessionId("session-a"));
    const provider = new SequencedDeferredProvider(transcripts.operations);
    const { runtime, session: firstSession } = createRunnerSession({
      transcripts,
      provider
    });
    const secondSession = {
      id: sessionId("session-b"),
      agentId: agentId("agent-default"),
      runtime,
      metadata: {
        sessionStartedAt: "2026-05-10T00:00:00.000Z",
        lastInteractionAt: null,
        updatedAt: "2026-05-10T00:00:00.000Z",
        attributes: {}
      }
    };
    const runner = new AgentRunner();

    const firstPromise = runner.runTurn(firstSession, {
      content: "first session"
    });
    await flushMicrotasks();
    expect(provider.requests).toHaveLength(1);

    const secondPromise = runner.runTurn(secondSession, {
      content: "second session"
    });
    await flushMicrotasks();

    expect(provider.requests).toHaveLength(2);
    expect(transcripts.operations).toContain("provider:chat:first session");
    expect(transcripts.operations).toContain("provider:chat:second session");

    provider.resolveByLabel("second session", "second reply");
    provider.resolveByLabel("first session", "first reply");

    await expect(secondPromise).resolves.toMatchObject({
      ok: true,
      value: expect.objectContaining({
        content: "second reply"
      })
    });
    await expect(firstPromise).resolves.toMatchObject({
      ok: true,
      value: expect.objectContaining({
        content: "first reply"
      })
    });
  });

  it("continues a same-session queue after a failed turn", async () => {
    const transcripts = new RecordingTranscriptStore(sessionId("session-runner"));
    const provider = new SequencedDeferredProvider(transcripts.operations);
    const { session } = createRunnerSession({
      transcripts,
      provider
    });
    const runner = new AgentRunner();

    const firstPromise = runner.runTurn(session, {
      content: "fail first"
    });
    await flushMicrotasks();
    const secondPromise = runner.runTurn(session, {
      content: "recover second"
    });
    await flushMicrotasks();
    expect(provider.requests).toHaveLength(1);

    provider.rejectNext(
      new AppError({
        code: "provider.execution_failed",
        message: "Provider failed once"
      })
    );
    const first = await firstPromise;
    await flushMicrotasks();

    expect(first.ok).toBe(false);
    expect(provider.requests).toHaveLength(2);

    provider.resolveNext("recovered");
    const second = await secondPromise;

    expect(second.ok).toBe(true);
    if (second.ok) {
      expect(second.value.content).toBe("recovered");
    }
    expect(transcripts.events.map((event) => event.type)).toEqual([
      "lifecycle",
      "user",
      "error",
      "lifecycle",
      "user",
      "assistant"
    ]);
  });

  it("continues a same-session queue after a timed-out turn", async () => {
    vi.useFakeTimers();
    try {
      const transcripts = new RecordingTranscriptStore(sessionId("session-runner"));
      const provider = new SequencedDeferredProvider(transcripts.operations);
      const { session } = createRunnerSession({
        transcripts,
        provider
      });
      const runner = new AgentRunner();

      const firstPromise = runner.runTurn(
        session,
        {
          content: "timeout first"
        },
        {
          timeoutMs: 25
        }
      );
      await flushMicrotasks();
      const secondPromise = runner.runTurn(session, {
        content: "after timeout"
      });
      await flushMicrotasks();
      expect(provider.requests).toHaveLength(1);

      await vi.advanceTimersByTimeAsync(25);
      const first = await firstPromise;
      await flushMicrotasks();

      expect(first.ok).toBe(false);
      if (!first.ok) {
        expect(first.error.code).toBe("agent.turn_timed_out");
      }
      expect(provider.requests).toHaveLength(2);

      provider.resolveByLabel("after timeout", "still runs");
      const second = await secondPromise;

      expect(second.ok).toBe(true);
      if (second.ok) {
        expect(second.value.content).toBe("still runs");
      }
    } finally {
      vi.useRealTimers();
    }
  });

  it("returns a safe failure and appends an awaited error transcript event when provider permission is denied", async () => {
    const transcripts = new RecordingTranscriptStore(sessionId("session-runner"));
    const audit = new InMemoryAuditSink();
    const eventSubscriber = new RecordingRuntimeEventSubscriber();
    const eventBus = new LocalRuntimeEventBus(logger);
    eventBus.subscribe(eventSubscriber.handle);
    const deniedProvider = new MockProvider(new DefaultDenyPolicy(), {
      audit,
      clock: new FixedClock("2026-05-10T00:00:00.000Z"),
      idGenerator: new SequentialIdGenerator({ eventPrefix: "provider-denied-audit" }),
      sessionId: sessionId("session-runner")
    });
    const { session } = createRunnerSession({
      transcripts,
      provider: deniedProvider,
      audit,
      eventBus,
      policy: new DefaultDenyPolicy(),
      clock: new FixedClock("2026-05-10T00:00:00.000Z"),
      idGenerator: new SequentialIdGenerator()
    });

    const result = await new AgentRunner().runTurn(session, {
      content: "deny this"
    });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe("provider.permission_denied");
      expect(result.error.message).toBe("Provider permission denied: mock");
    }
    expect(transcripts.operations).toEqual([
      "append:start:lifecycle",
      "append:end:lifecycle",
      "append:start:user",
      "append:end:user",
      "read",
      "append:start:error",
      "append:end:error"
    ]);
    expect(transcripts.events.map((event) => event.type)).toEqual(["lifecycle", "user", "error"]);
    expect(transcripts.events[2]).toMatchObject({
      type: "error",
      payload: {
        errorName: "AppError",
        message: "Provider permission denied: mock",
        code: "provider.permission_denied"
      }
    });
    expect(eventSubscriber.listEvents()).toEqual([
      expect.objectContaining({
        type: "provider.call_requested",
        eventId: eventId("event-2"),
        timestamp: "2026-05-10T00:00:00.000Z",
        sessionId: sessionId("session-runner"),
        payload: {
          providerName: providerName("mock"),
          messageCount: 1
        }
      }),
      expect.objectContaining({
        type: "provider.call_failed",
        eventId: eventId("event-6"),
        timestamp: "2026-05-10T00:00:00.000Z",
        sessionId: sessionId("session-runner"),
        payload: {
          providerName: providerName("mock"),
          errorCode: "provider.permission_denied",
          errorMessage: "Provider permission denied: mock"
        }
      })
    ]);
    expect(audit.listEvents()).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          sourcePackage: "@dominic-nexus/core",
          action: "provider.call_requested",
          decision: "pending",
          outcome: "requested",
          sessionId: sessionId("session-runner")
        }),
        expect.objectContaining({
          action: "permission.decide",
          decision: "denied",
          outcome: "denied",
          sessionId: sessionId("session-runner")
        }),
        expect.objectContaining({
          action: "provider.call",
          decision: "denied",
          outcome: "denied",
          sessionId: sessionId("session-runner"),
          resource: expect.objectContaining({
            id: "mock"
          })
        }),
        expect.objectContaining({
          sourcePackage: "@dominic-nexus/core",
          action: "provider.call_failed",
          decision: "denied",
          outcome: "denied",
          sessionId: sessionId("session-runner")
        })
      ])
    );
  });

  it("returns provider failure only after the error transcript append has completed", async () => {
    const transcripts = new RecordingTranscriptStore(sessionId("session-runner"));
    const providerFailure = new AppError({
      code: "provider.execution_failed",
      message: "Provider failed safely",
      context: {
        providerName: "mock"
      }
    });
    const { session } = createRunnerSession({
      transcripts,
      provider: new ThrowingProvider(providerFailure, transcripts.operations)
    });

    const result = await new AgentRunner().runTurn(session, {
      content: "fail this"
    });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe("provider.execution_failed");
    }
    expect(transcripts.operations.at(-1)).toBe("append:end:error");
    expect(transcripts.events.map((event) => event.type)).toEqual(["lifecycle", "user", "error"]);
  });

  it("returns a typed timeout failure without emitting provider success or touching the session", async () => {
    vi.useFakeTimers();
    try {
      const audit = new InMemoryAuditSink();
      const eventSubscriber = new RecordingRuntimeEventSubscriber();
      const eventBus = new LocalRuntimeEventBus(logger);
      eventBus.subscribe(eventSubscriber.handle);
      const transcripts = new RecordingTranscriptStore(sessionId("session-runner"));
      const provider = new DeferredProvider(transcripts.operations);
      const sessions = new RecordingSessionStore(
        ok({
          id: sessionId("session-runner"),
          agentId: agentId("agent-default"),
          metadata: {
            sessionStartedAt: "2026-05-10T00:00:00.000Z",
            lastInteractionAt: "2026-05-10T00:01:00.000Z",
            updatedAt: "2026-05-10T00:01:00.000Z",
            attributes: {}
          }
        })
      );
      const { session } = createRunnerSession({
        transcripts,
        provider,
        sessions,
        audit,
        eventBus,
        clock: new FixedClock("2026-05-10T00:00:00.000Z"),
        idGenerator: new SequentialIdGenerator()
      });

      const resultPromise = new AgentRunner().runTurn(
        session,
        {
          content: "timeout this",
          model: "mock/default"
        },
        {
          timeoutMs: 50
        }
      );
      await flushMicrotasks();

      expect(provider.requests).toHaveLength(1);
      expect(provider.requests[0]?.signal?.aborted).toBe(false);

      await vi.advanceTimersByTimeAsync(50);
      const result = await resultPromise;

      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.error.code).toBe("agent.turn_timed_out");
        expect(result.error.context).toEqual({
          providerName: "mock",
          timeoutMs: 50
        });
      }
      expect(provider.requests[0]?.signal?.aborted).toBe(true);
      expect(sessions.operations).toEqual([]);
      expect(transcripts.events.map((event) => event.type)).toEqual(["lifecycle", "user", "error"]);
      expect(transcripts.events[2]).toMatchObject({
        type: "error",
        payload: {
          code: "agent.turn_timed_out"
        }
      });
      expect(eventSubscriber.listEvents().map((event) => event.type)).toEqual([
        "provider.call_requested",
        "provider.call_failed"
      ]);
      expect(eventSubscriber.listEvents()[1]).toMatchObject({
        type: "provider.call_failed",
        payload: {
          providerName: providerName("mock"),
          model: "mock/default",
          errorCode: "agent.turn_timed_out",
          errorMessage: "Agent turn timed out after 50ms: mock"
        }
      });
      expect(audit.listEvents()).toEqual([
        expect.objectContaining({
          sourcePackage: "@dominic-nexus/core",
          action: "provider.call_requested",
          decision: "pending",
          outcome: "requested",
          metadata: expect.objectContaining({
            messageCount: 1,
            model: "mock/default"
          })
        }),
        expect.objectContaining({
          sourcePackage: "@dominic-nexus/permissions",
          action: "permission.decide",
          decision: "allowed",
          outcome: "succeeded",
          resource: expect.objectContaining({
            id: "provider.call"
          })
        }),
        expect.objectContaining({
          sourcePackage: "@dominic-nexus/core",
          action: "provider.call_failed",
          decision: "not_applicable",
          outcome: "failed",
          metadata: expect.objectContaining({
            errorCode: "agent.turn_timed_out",
            messageCount: 1,
            model: "mock/default"
          })
        })
      ]);

      provider.resolve();
      await flushMicrotasks();
      expect(eventSubscriber.listEvents().map((event) => event.type)).toEqual([
        "provider.call_requested",
        "provider.call_failed"
      ]);
      expect(transcripts.events.map((event) => event.type)).toEqual(["lifecycle", "user", "error"]);
    } finally {
      vi.useRealTimers();
    }
  });

  it("ignores provider resolution in the same tick as timeout expiry when using injected timers", async () => {
    let timeoutCallback: (() => void) | undefined;
    const timers: AgentRunnerTimers = {
      setTimeout(handler) {
        timeoutCallback = handler;
        return {} as ReturnType<typeof setTimeout>;
      },
      clearTimeout() {}
    };
    const eventSubscriber = new RecordingRuntimeEventSubscriber();
    const eventBus = new LocalRuntimeEventBus(logger);
    eventBus.subscribe(eventSubscriber.handle);
    const transcripts = new RecordingTranscriptStore(sessionId("session-runner"));
    const provider = new DeferredProvider(transcripts.operations);
    const sessions = new RecordingSessionStore(
      ok({
        id: sessionId("session-runner"),
        agentId: agentId("agent-default"),
        metadata: {
          sessionStartedAt: "2026-05-10T00:00:00.000Z",
          lastInteractionAt: "2026-05-10T00:01:00.000Z",
          updatedAt: "2026-05-10T00:01:00.000Z",
          attributes: {}
        }
      })
    );
    const { session } = createRunnerSession({
      transcripts,
      provider,
      sessions,
      eventBus,
      clock: new FixedClock("2026-05-10T00:00:00.000Z"),
      idGenerator: new SequentialIdGenerator()
    });

    const resultPromise = new AgentRunner({ timers }).runTurn(
      session,
      {
        content: "timeout race"
      },
      {
        timeoutMs: 50
      }
    );
    await flushMicrotasks();

    expect(provider.requests).toHaveLength(1);
    expect(timeoutCallback).toBeDefined();
    timeoutCallback?.();
    provider.resolve();

    const result = await resultPromise;

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe("agent.turn_timed_out");
    }
    expect(sessions.operations).toEqual([]);
    expect(transcripts.events.map((event) => event.type)).toEqual(["lifecycle", "user", "error"]);
    expect(eventSubscriber.listEvents().map((event) => event.type)).toEqual([
      "provider.call_requested",
      "provider.call_failed"
    ]);

    await flushMicrotasks();
    expect(transcripts.events.map((event) => event.type)).toEqual(["lifecycle", "user", "error"]);
    expect(eventSubscriber.listEvents().map((event) => event.type)).toEqual([
      "provider.call_requested",
      "provider.call_failed"
    ]);
  });

  it("clears injected timeout and completes normally when provider succeeds before timeout", async () => {
    const timeoutHandle = {} as ReturnType<typeof setTimeout>;
    const clearTimeoutMock = vi.fn();
    const timers: AgentRunnerTimers = {
      setTimeout() {
        return timeoutHandle;
      },
      clearTimeout: clearTimeoutMock
    };
    const eventSubscriber = new RecordingRuntimeEventSubscriber();
    const eventBus = new LocalRuntimeEventBus(logger);
    eventBus.subscribe(eventSubscriber.handle);
    const transcripts = new RecordingTranscriptStore(sessionId("session-runner"));
    const provider = new RecordingProvider(transcripts.operations, providerName("mock"), {
      message: {
        role: "assistant",
        content: "fast reply"
      }
    });
    const sessions = new RecordingSessionStore(
      ok({
        id: sessionId("session-runner"),
        agentId: agentId("agent-default"),
        metadata: {
          sessionStartedAt: "2026-05-10T00:00:00.000Z",
          lastInteractionAt: "2026-05-10T00:01:00.000Z",
          updatedAt: "2026-05-10T00:01:00.000Z",
          attributes: {}
        }
      })
    );
    const { session } = createRunnerSession({
      transcripts,
      provider,
      sessions,
      eventBus,
      clock: new FixedClock("2026-05-10T00:00:00.000Z"),
      idGenerator: new SequentialIdGenerator()
    });

    const result = await new AgentRunner({ timers }).runTurn(
      session,
      {
        content: "fast path"
      },
      {
        timeoutMs: 50
      }
    );

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value.content).toBe("fast reply");
    }
    expect(clearTimeoutMock).toHaveBeenCalledWith(timeoutHandle);
    expect(provider.requests).toHaveLength(1);
    expect(provider.requests[0]?.signal?.aborted).toBe(false);
    expect(transcripts.events.map((event) => event.type)).toEqual(["lifecycle", "user", "assistant"]);
    expect(sessions.operations).toEqual(["session:update:session-runner"]);
    expect(eventSubscriber.listEvents().map((event) => event.type)).toEqual([
      "provider.call_requested",
      "provider.call_succeeded",
      "session.updated"
    ]);
  });

  it("returns a typed cancellation failure without calling provider when the caller has already aborted", async () => {
    const audit = new InMemoryAuditSink();
    const eventSubscriber = new RecordingRuntimeEventSubscriber();
    const eventBus = new LocalRuntimeEventBus(logger);
    eventBus.subscribe(eventSubscriber.handle);
    const transcripts = new RecordingTranscriptStore(sessionId("session-runner"));
    const provider = new RecordingProvider(transcripts.operations);
    const controller = new AbortController();
    controller.abort();
    const { session } = createRunnerSession({
      transcripts,
      provider,
      audit,
      eventBus,
      clock: new FixedClock("2026-05-10T00:00:00.000Z"),
      idGenerator: new SequentialIdGenerator()
    });

    const result = await new AgentRunner().runTurn(
      session,
      {
        content: "cancel this"
      },
      {
        signal: controller.signal
      }
    );

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe("agent.turn_cancelled");
    }
    expect(provider.requests).toEqual([]);
    expect(transcripts.operations).toEqual([
      "append:start:lifecycle",
      "append:end:lifecycle",
      "append:start:user",
      "append:end:user",
      "read",
      "append:start:error",
      "append:end:error"
    ]);
    expect(transcripts.events.map((event) => event.type)).toEqual(["lifecycle", "user", "error"]);
    expect(eventSubscriber.listEvents().map((event) => event.type)).toEqual([
      "provider.call_requested",
      "provider.call_failed"
    ]);
    expect(audit.listEvents()).toEqual([
      expect.objectContaining({
        action: "provider.call_requested",
        decision: "pending",
        outcome: "requested",
        metadata: expect.objectContaining({
          messageCount: 1
        })
      }),
      expect.objectContaining({
        action: "provider.call_failed",
        decision: "not_applicable",
        outcome: "failed",
        metadata: expect.objectContaining({
          errorCode: "agent.turn_cancelled",
          messageCount: 1
        })
      })
    ]);
  });

  it("returns a typed cancellation failure and ignores late provider resolution", async () => {
    const eventSubscriber = new RecordingRuntimeEventSubscriber();
    const eventBus = new LocalRuntimeEventBus(logger);
    eventBus.subscribe(eventSubscriber.handle);
    const transcripts = new RecordingTranscriptStore(sessionId("session-runner"));
    const provider = new DeferredProvider(transcripts.operations);
    const sessions = new RecordingSessionStore(
      ok({
        id: sessionId("session-runner"),
        agentId: agentId("agent-default"),
        metadata: {
          sessionStartedAt: "2026-05-10T00:00:00.000Z",
          lastInteractionAt: "2026-05-10T00:01:00.000Z",
          updatedAt: "2026-05-10T00:01:00.000Z",
          attributes: {}
        }
      })
    );
    const controller = new AbortController();
    const { session } = createRunnerSession({
      transcripts,
      provider,
      sessions,
      eventBus,
      clock: new FixedClock("2026-05-10T00:00:00.000Z"),
      idGenerator: new SequentialIdGenerator()
    });

    const resultPromise = new AgentRunner().runTurn(
      session,
      {
        content: "cancel in flight"
      },
      {
        signal: controller.signal
      }
    );
    await flushMicrotasks();
    expect(provider.requests).toHaveLength(1);
    expect(provider.requests[0]?.signal?.aborted).toBe(false);

    controller.abort();
    const result = await resultPromise;

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe("agent.turn_cancelled");
    }
    expect(provider.requests[0]?.signal?.aborted).toBe(true);
    expect(sessions.operations).toEqual([]);
    expect(transcripts.events.map((event) => event.type)).toEqual(["lifecycle", "user", "error"]);
    expect(eventSubscriber.listEvents().map((event) => event.type)).toEqual([
      "provider.call_requested",
      "provider.call_failed"
    ]);

    provider.resolve();
    await flushMicrotasks();
    expect(eventSubscriber.listEvents().map((event) => event.type)).toEqual([
      "provider.call_requested",
      "provider.call_failed"
    ]);
    expect(transcripts.events.map((event) => event.type)).toEqual(["lifecycle", "user", "error"]);
  });

  it("rejects invalid timeout options before writing transcript events", async () => {
    const transcripts = new RecordingTranscriptStore(sessionId("session-runner"));
    const provider = new RecordingProvider(transcripts.operations);
    const { session } = createRunnerSession({
      transcripts,
      provider
    });

    const result = await new AgentRunner().runTurn(
      session,
      {
        content: "hello"
      },
      {
        timeoutMs: 0
      }
    );

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe("agent.invalid_input");
    }
    expect(transcripts.operations).toEqual([]);
    expect(provider.requests).toEqual([]);
  });

  it("reports missing providers as typed failures with recoverable transcript history", async () => {
    const audit = new InMemoryAuditSink();
    const eventSubscriber = new RecordingRuntimeEventSubscriber();
    const eventBus = new LocalRuntimeEventBus(logger);
    eventBus.subscribe(eventSubscriber.handle);
    const failureLogger = createLogger();
    const transcripts = new RecordingTranscriptStore(sessionId("session-runner"));
    const { session } = createRunnerSession({
      transcripts,
      audit,
      logger: failureLogger,
      eventBus,
      clock: new FixedClock("2026-05-10T00:00:00.000Z"),
      idGenerator: new SequentialIdGenerator()
    });

    const result = await new AgentRunner().runTurn(session, {
      content: "hello",
      providerName: providerName("missing")
    });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe("agent.provider_not_found");
    }
    expect(transcripts.events.map((event) => event.type)).toEqual(["lifecycle", "user", "error"]);
    expect(transcripts.events[2]).toMatchObject({
      type: "error",
      payload: {
        code: "agent.provider_not_found"
      }
    });
    expect(audit.listEvents()).toEqual([
      expect.objectContaining({
        sourcePackage: "@dominic-nexus/core",
        action: "provider.call_requested",
        decision: "pending",
        outcome: "requested",
        sessionId: sessionId("session-runner"),
        metadata: expect.objectContaining({
          messageCount: 1
        })
      }),
      expect.objectContaining({
        sourcePackage: "@dominic-nexus/core",
        action: "provider.call_failed",
        decision: "not_applicable",
        outcome: "failed",
        sessionId: sessionId("session-runner"),
        metadata: expect.objectContaining({
          errorCode: "agent.provider_not_found",
          messageCount: 1
        })
      })
    ]);
    expect(eventSubscriber.listEvents()).toEqual([
      expect.objectContaining({
        type: "provider.call_requested",
        eventId: eventId("event-2"),
        timestamp: "2026-05-10T00:00:00.000Z",
        sessionId: sessionId("session-runner"),
        payload: {
          providerName: providerName("missing"),
          messageCount: 1
        }
      }),
      expect.objectContaining({
        type: "provider.call_failed",
        eventId: eventId("event-4"),
        timestamp: "2026-05-10T00:00:00.000Z",
        sessionId: sessionId("session-runner"),
        payload: {
          providerName: providerName("missing"),
          errorCode: "agent.provider_not_found",
          errorMessage: "Provider not found: missing"
        }
      })
    ]);
    expect(failureLogger.warn).toHaveBeenCalledWith("Agent turn failed", {
      sessionId: "session-runner",
      errorCode: "agent.provider_not_found",
      errorMessage: "Provider not found: missing",
      phase: "provider.lookup",
      providerName: "missing"
    });
  });

  it("allows non-persisted sessions to complete while reporting sessionUpdate.persisted false", async () => {
    const transcripts = new RecordingTranscriptStore(sessionId("session-runner"));
    const provider = new RecordingProvider(transcripts.operations);
    const { session } = createRunnerSession({
      transcripts,
      provider
    });

    const result = await new AgentRunner().runTurn(session, {
      content: "hello"
    });

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value.sessionUpdate).toEqual({
        persisted: false
      });
    }
    expect(transcripts.events.map((event) => event.type)).toEqual(["lifecycle", "user", "assistant"]);
  });

  it("appends an error event when session metadata update fails for a persisted session", async () => {
    const failureLogger = createLogger();
    const transcripts = new RecordingTranscriptStore(sessionId("session-runner"));
    const provider = new RecordingProvider(transcripts.operations);
    const sessions = new RecordingSessionStore(
      err(
        new AppError({
          code: "session.write_failed",
          message: "Session update failed safely"
        })
      )
    );
    const { session } = createRunnerSession({
      transcripts,
      provider,
      sessions,
      logger: failureLogger
    });

    const result = await new AgentRunner().runTurn(session, {
      content: "hello"
    });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe("session.write_failed");
    }
    expect(transcripts.operations.at(-1)).toBe("append:end:error");
    expect(transcripts.events.map((event) => event.type)).toEqual(["lifecycle", "user", "assistant", "error"]);
    expect(failureLogger.warn).toHaveBeenCalledWith("Agent turn failed", {
      sessionId: "session-runner",
      errorCode: "session.write_failed",
      errorMessage: "Session update failed safely",
      phase: "session.touch",
      providerName: "mock"
    });
  });

  it("rejects empty normalized user input without writing transcript events", async () => {
    const transcripts = new RecordingTranscriptStore(sessionId("session-runner"));
    const provider = new RecordingProvider(transcripts.operations);
    const { session } = createRunnerSession({
      transcripts,
      provider
    });

    const result = await new AgentRunner().runTurn(session, {
      content: "   "
    });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe("agent.invalid_input");
    }
    expect(transcripts.operations).toEqual([]);
    expect(provider.requests).toEqual([]);
  });

  it("appends an error event if transcript context assembly fails before provider call", async () => {
    const eventSubscriber = new RecordingRuntimeEventSubscriber();
    const eventBus = new LocalRuntimeEventBus(logger);
    eventBus.subscribe(eventSubscriber.handle);
    const transcripts = new FailingReadTranscriptStore(sessionId("session-runner"));
    const provider = new RecordingProvider(transcripts.operations);
    const { session } = createRunnerSession({
      transcripts,
      provider,
      eventBus,
      clock: new FixedClock("2026-05-10T00:00:00.000Z"),
      idGenerator: new SequentialIdGenerator()
    });

    const result = await new AgentRunner().runTurn(session, {
      content: "hello"
    });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe("transcript.read_failed");
    }
    expect(provider.requests).toEqual([]);
    expect(transcripts.operations).toEqual([
      "append:start:lifecycle",
      "append:end:lifecycle",
      "append:start:user",
      "append:end:user",
      "read",
      "append:start:error",
      "append:end:error"
    ]);
    expect(eventSubscriber.listEvents()).toEqual([
      expect.objectContaining({
        type: "lifecycle.runtime_failed",
        eventId: eventId("event-2"),
        timestamp: "2026-05-10T00:00:00.000Z",
        sessionId: sessionId("session-runner"),
        payload: {
          errorCode: "transcript.read_failed",
          errorMessage: "Transcript read failed in test"
        }
      })
    ]);
  });

  it("returns lifecycle append failures without calling provider", async () => {
    const failureLogger = createLogger();
    const transcripts = new FailingAppendTranscriptStore(sessionId("session-runner"), 1);
    const provider = new RecordingProvider(transcripts.operations);
    const { session } = createRunnerSession({
      transcripts,
      provider,
      logger: failureLogger
    });

    const result = await new AgentRunner().runTurn(session, {
      content: "hello"
    });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe("transcript.write_failed");
    }
    expect(provider.requests).toEqual([]);
    expect(transcripts.operations).toEqual(["append:start:lifecycle", "append:failed:lifecycle"]);
    expect(failureLogger.warn).toHaveBeenCalledWith("Agent turn failed", {
      sessionId: "session-runner",
      errorCode: "transcript.write_failed",
      errorMessage: "Transcript append failed in test: lifecycle",
      phase: "lifecycle.append"
    });
  });

  it("returns user append failures without reading context or calling provider", async () => {
    const transcripts = new FailingAppendTranscriptStore(sessionId("session-runner"), 2);
    const provider = new RecordingProvider(transcripts.operations);
    const { session } = createRunnerSession({
      transcripts,
      provider
    });

    const result = await new AgentRunner().runTurn(session, {
      content: "hello"
    });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe("transcript.write_failed");
    }
    expect(provider.requests).toEqual([]);
    expect(transcripts.operations).toEqual([
      "append:start:lifecycle",
      "append:end:lifecycle",
      "append:start:user",
      "append:failed:user"
    ]);
  });

  it("returns assistant append failures without touching session metadata", async () => {
    const transcripts = new FailingAppendTranscriptStore(sessionId("session-runner"), 3);
    const provider = new RecordingProvider(transcripts.operations);
    const sessions = new RecordingSessionStore(
      ok({
        id: sessionId("session-runner"),
        agentId: agentId("agent-default"),
        metadata: {
          sessionStartedAt: "2026-05-10T00:00:00.000Z",
          lastInteractionAt: "2026-05-10T00:01:00.000Z",
          updatedAt: "2026-05-10T00:01:00.000Z",
          attributes: {}
        }
      })
    );
    const { session } = createRunnerSession({
      transcripts,
      provider,
      sessions
    });

    const result = await new AgentRunner().runTurn(session, {
      content: "hello"
    });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe("transcript.write_failed");
    }
    expect(provider.requests).toHaveLength(1);
    expect(sessions.operations).toEqual([]);
    expect(transcripts.operations).toEqual([
      "append:start:lifecycle",
      "append:end:lifecycle",
      "append:start:user",
      "append:end:user",
      "read",
      "provider:chat",
      "append:start:assistant",
      "append:failed:assistant"
    ]);
  });
});

describe("createRuntimeDomainEvent", () => {
  it("creates deterministic event ids and timestamps from injected runtime utilities", () => {
    const runtime = createRuntimeContext({
      config,
      logger,
      policy: new AllowAllDevelopmentPolicy(),
      clock: new FixedClock("2026-05-07T00:00:00.000Z"),
      idGenerator: new SequentialIdGenerator()
    });

    const session = createAgentSession(runtime);
    const event = createRuntimeDomainEvent(runtime, {
      type: "session.created",
      sourcePackage: "@dominic-nexus/core",
      sessionId: session.id,
      payload: {
        agentId: session.agentId
      }
    });

    expect(event).toEqual({
      type: "session.created",
      eventId: eventId("event-1"),
      timestamp: "2026-05-07T00:00:00.000Z",
      sourcePackage: "@dominic-nexus/core",
      sessionId: sessionId("session-1"),
      payload: {
        agentId: agentId("agent-default")
      }
    });
  });
});

describe("LocalRuntimeEventBus", () => {
  it("emits deterministic event snapshots to subscribers in order", async () => {
    const subscriber = new RecordingRuntimeEventSubscriber();
    const runtime = createRuntimeContext({
      config,
      logger,
      policy: new AllowAllDevelopmentPolicy(),
      eventBus: new LocalRuntimeEventBus(logger),
      clock: new FixedClock("2026-05-07T00:00:00.000Z"),
      idGenerator: new SequentialIdGenerator()
    });
    runtime.eventBus.subscribe(subscriber.handle);
    const session = createAgentSession(runtime);

    await emitRuntimeDomainEvent(runtime, {
      type: "session.created",
      sourcePackage: "@dominic-nexus/core",
      sessionId: session.id,
      payload: {
        agentId: session.agentId
      }
    });
    await emitRuntimeDomainEvent(runtime, {
      type: "session.updated",
      sourcePackage: "@dominic-nexus/core",
      sessionId: session.id,
      payload: {
        reason: "test"
      }
    });

    expect(subscriber.listEvents()).toEqual([
      {
        type: "session.created",
        eventId: eventId("event-1"),
        timestamp: "2026-05-07T00:00:00.000Z",
        sourcePackage: "@dominic-nexus/core",
        sessionId: sessionId("session-1"),
        payload: {
          agentId: agentId("agent-default")
        }
      },
      {
        type: "session.updated",
        eventId: eventId("event-2"),
        timestamp: "2026-05-07T00:00:00.000Z",
        sourcePackage: "@dominic-nexus/core",
        sessionId: sessionId("session-1"),
        payload: {
          reason: "test"
        }
      }
    ]);
  });

  it("gives subscribers immutable cloned event snapshots", async () => {
    const bus = new LocalRuntimeEventBus(logger);
    const seen: DomainEvent[] = [];
    bus.subscribe((event) => {
      try {
        (event.payload as { reason: string }).reason = "mutated";
        (event.payload as { metadata: { nested: string } }).metadata.nested = "mutated";
      } catch {
        // Frozen snapshots throw in strict mode; either way the next subscriber must see the original event.
      }
    });
    bus.subscribe((event) => {
      seen.push(event);
    });

    await bus.emit({
      type: "session.updated",
      eventId: eventId("event-immutable"),
      timestamp: "2026-05-07T00:00:00.000Z",
      sourcePackage: "@dominic-nexus/core",
      sessionId: sessionId("session-immutable"),
      payload: {
        reason: "original",
        metadata: {
          nested: "original"
        }
      }
    });

    expect(seen).toEqual([
      {
        type: "session.updated",
        eventId: eventId("event-immutable"),
        timestamp: "2026-05-07T00:00:00.000Z",
        sourcePackage: "@dominic-nexus/core",
        sessionId: sessionId("session-immutable"),
        payload: {
          reason: "original",
          metadata: {
            nested: "original"
          }
        }
      }
    ]);
    expect(Object.isFrozen(seen[0])).toBe(true);
    expect(Object.isFrozen(seen[0]?.payload)).toBe(true);
    expect(Object.isFrozen((seen[0]?.payload as { metadata?: object }).metadata)).toBe(true);
  });

  it("stops delivery after unsubscribe", async () => {
    const bus = new LocalRuntimeEventBus(logger);
    const subscriber = new RecordingRuntimeEventSubscriber();
    const subscription = bus.subscribe(subscriber.handle);
    subscription.unsubscribe();

    await bus.emit({
      type: "session.updated",
      eventId: eventId("event-unsubscribed"),
      timestamp: "2026-05-07T00:00:00.000Z",
      sourcePackage: "@dominic-nexus/core",
      sessionId: sessionId("session-unsubscribed"),
      payload: {
        reason: "unsubscribe-test"
      }
    });

    expect(subscriber.count()).toBe(0);
  });

  it("emits with no subscribers without failing", async () => {
    const bus = new LocalRuntimeEventBus(logger);

    await expect(
      bus.emit({
        type: "session.updated",
        eventId: eventId("event-no-subscribers"),
        timestamp: "2026-05-07T00:00:00.000Z",
        sourcePackage: "@dominic-nexus/core",
        sessionId: sessionId("session-no-subscribers"),
        payload: {
          reason: "no-subscribers-test"
        }
      })
    ).resolves.toBeUndefined();
  });

  it("contains subscriber failures and logs safe event metadata", async () => {
    const failureLogger = createLogger();
    const bus = new LocalRuntimeEventBus(failureLogger);
    const subscriber = new RecordingRuntimeEventSubscriber();
    bus.subscribe(() => {
      throw new Error("subscriber secret should not be logged");
    });
    bus.subscribe(subscriber.handle);

    await bus.emit({
      type: "session.updated",
      eventId: eventId("event-failure"),
      timestamp: "2026-05-07T00:00:00.000Z",
      sourcePackage: "@dominic-nexus/core",
      sessionId: sessionId("session-failure"),
      payload: {
        reason: "failure-test"
      }
    });

    expect(subscriber.count()).toBe(1);
    expect(failureLogger.warn).toHaveBeenCalledWith("Runtime event subscriber failed", {
      eventId: "event-failure",
      eventType: "session.updated",
      sourcePackage: "@dominic-nexus/core",
      errorName: "Error"
    });
  });

  it("contains rejected async subscriber failures and continues delivery", async () => {
    const failureLogger = createLogger();
    const bus = new LocalRuntimeEventBus(failureLogger);
    const subscriber = new RecordingRuntimeEventSubscriber();
    bus.subscribe(async () => {
      await Promise.resolve();
      throw new Error("async subscriber secret should not be logged");
    });
    bus.subscribe(subscriber.handle);

    await bus.emit({
      type: "session.updated",
      eventId: eventId("event-async-failure"),
      timestamp: "2026-05-07T00:00:00.000Z",
      sourcePackage: "@dominic-nexus/core",
      sessionId: sessionId("session-async-failure"),
      payload: {
        reason: "async-failure-test"
      }
    });

    expect(subscriber.count()).toBe(1);
    expect(failureLogger.warn).toHaveBeenCalledWith("Runtime event subscriber failed", {
      eventId: "event-async-failure",
      eventType: "session.updated",
      sourcePackage: "@dominic-nexus/core",
      errorName: "Error"
    });
  });
});

describe("startRuntime", () => {
  it("logs startup metadata with a session id when provided", async () => {
    const subscriber = new RecordingRuntimeEventSubscriber();
    const runtime = createRuntimeContext({
      config,
      logger,
      policy: new AllowAllDevelopmentPolicy(),
      eventBus: new LocalRuntimeEventBus(logger),
      clock: new FixedClock("2026-05-07T00:00:00.000Z"),
      idGenerator: new SequentialIdGenerator()
    });
    runtime.eventBus.subscribe(subscriber.handle);
    const session = createAgentSession(runtime);

    await startRuntime(runtime, session);

    expect(logger.info).toHaveBeenCalledWith("Runtime started", {
      appName: "Test Nexus",
      environment: "test",
      sessionId: "session-1"
    });
    expect(subscriber.listEvents()).toEqual([
      {
        type: "lifecycle.runtime_started",
        eventId: eventId("event-1"),
        timestamp: "2026-05-07T00:00:00.000Z",
        sourcePackage: "@dominic-nexus/core",
        sessionId: sessionId("session-1"),
        payload: {
          appName: "Test Nexus",
          environment: "test"
        }
      }
    ]);
  });

  it("logs null session id when no session is provided", async () => {
    const loggerWithoutSession = {
      debug: vi.fn(),
      info: vi.fn(),
      warn: vi.fn(),
      error: vi.fn()
    };
    const runtime = createRuntimeContext({
      config,
      logger: loggerWithoutSession,
      policy: new AllowAllDevelopmentPolicy()
    });

    await startRuntime(runtime);

    expect(loggerWithoutSession.info).toHaveBeenCalledWith("Runtime started", {
      appName: "Test Nexus",
      environment: "test",
      sessionId: null
    });
  });
});
