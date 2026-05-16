import { appendAuditEvent, InMemoryAuditSink, type AuditSink } from "@dominic-nexus/audit";
import type { AppConfig } from "@dominic-nexus/config";
import type { Logger } from "@dominic-nexus/logging";
import { InMemoryStore, type MemoryStore } from "@dominic-nexus/memory";
import type { PolicyEngine } from "@dominic-nexus/permissions";
import { ProviderRegistry, type ChatMessage, type ChatRequest, type ChatResponse } from "@dominic-nexus/providers";
import { EnvSecretStore, type SecretEnvSource, type SecretStore } from "@dominic-nexus/secrets";
import {
  FilesystemRootPolicy,
  registerEchoTool,
  registerReadFileTool,
  registerWebFetchTool,
  registerWriteFileTool,
  ToolRegistry
} from "@dominic-nexus/tools";
import {
  agentId,
  AppError,
  createDefaultRuntimeUtilities,
  createDomainEventFromRuntime,
  err,
  type AgentId,
  type Clock,
  type CreateDomainEventFromRuntimeOptions,
  type DomainEvent,
  type DomainEventType,
  type EventId,
  type IdGenerator,
  type JsonObject,
  type JsonValue,
  ok,
  providerName,
  toAppError,
  type ProviderName,
  type Result,
  type RuntimeUtilities,
  type SessionId
} from "@dominic-nexus/shared";
import { LocalRuntimeEventBus, type RuntimeEventBus } from "./event-bus.js";
import { createCliSessionRoutingKey, SessionTurnQueue, type SessionRoutingKey } from "./session-routing.js";
import { DirectorySessionStore, type SessionMetadata, type SessionStore } from "./session-store.js";
import {
  DirectoryTranscriptStore,
  type TranscriptAssistantPayload,
  type TranscriptErrorPayload,
  type TranscriptEvent,
  type TranscriptStore
} from "./transcript-store.js";

export {
  LocalRuntimeEventBus,
  RecordingRuntimeEventSubscriber,
  type RuntimeEventBus,
  type RuntimeEventSubscriber,
  type RuntimeEventSubscription
} from "./event-bus.js";

export {
  createChannelSessionRoutingKey,
  createCliSessionRoutingKey,
  parseSessionRoutingKey,
  SessionTurnQueue,
  type ChannelSessionRoutingInput,
  type ChannelSessionRoutingScope,
  type CliSessionRoutingInput,
  type SessionRoutingKey
} from "./session-routing.js";

export {
  DirectorySessionStore,
  type CreateSessionOptions,
  type DirectorySessionStoreOptions,
  type PersistedSession,
  type SessionMetadata,
  type SessionStore,
  type SessionStoreAccess,
  type UpdateSessionOptions
} from "./session-store.js";

export {
  DirectoryTranscriptStore,
  type AppendTranscriptEventInput,
  type DirectoryTranscriptStoreOptions,
  type MalformedTranscriptLine,
  type TranscriptAssistantPayload,
  type TranscriptErrorPayload,
  type TranscriptEvent,
  type TranscriptEventType,
  type TranscriptLifecyclePayload,
  type TranscriptPayloadMap,
  type TranscriptReadResult,
  type TranscriptStore,
  type TranscriptStoreAccess,
  type TranscriptToolPayload,
  type TranscriptToolPhase,
  type TranscriptUserPayload
} from "./transcript-store.js";

export interface RuntimeContext {
  config: AppConfig;
  logger: Logger;
  policy: PolicyEngine;
  audit: AuditSink;
  tools: ToolRegistry;
  providers: ProviderRegistry;
  memory: MemoryStore;
  secrets: SecretStore;
  sessions: SessionStore;
  transcripts: TranscriptStore;
  eventBus: RuntimeEventBus;
  filesystem: FilesystemRootPolicy;
  utilities: RuntimeUtilities;
  /** Convenience alias for runtime.utilities.clock. */
  clock: Clock;
  /** Convenience alias for runtime.utilities.idGenerator. */
  idGenerator: IdGenerator;
}

export interface RuntimeContextOptions {
  config: AppConfig;
  logger: Logger;
  policy: PolicyEngine;
  audit?: AuditSink;
  tools?: ToolRegistry;
  providers?: ProviderRegistry;
  memory?: MemoryStore;
  secrets?: SecretStore;
  sessions?: SessionStore;
  transcripts?: TranscriptStore;
  eventBus?: RuntimeEventBus;
  filesystem?: FilesystemRootPolicy;
  utilities?: RuntimeUtilities;
  clock?: Clock;
  idGenerator?: IdGenerator;
  secretEnv?: SecretEnvSource;
  filesystemRoots?: string[];
}

export interface AgentSession {
  id: SessionId;
  agentId: AgentId;
  runtime: RuntimeContext;
  metadata: SessionMetadata;
}

export interface AgentTurnInput {
  content: string;
  metadata?: JsonObject;
  model?: string;
  providerName?: ProviderName;
}

export interface AgentTurnOptions {
  /** Routing-only key for queue policy; this is not an authorization or identity boundary. */
  sessionRoutingKey?: SessionRoutingKey;
  signal?: AbortSignal;
  timeoutMs?: number;
}

export interface AgentTurnSessionUpdate {
  persisted: boolean;
  /** Present when a persisted session was touched; AgentRunner also updates the passed AgentSession.metadata reference. */
  metadata?: SessionMetadata;
}

export interface AgentTurnTranscriptEvents {
  lifecycle: EventId;
  user: EventId;
  assistant: EventId;
}

export interface AgentTurnResponse {
  content: string;
  message: ChatMessage;
  providerName: ProviderName;
  model?: string;
  transcriptEvents: AgentTurnTranscriptEvents;
  sessionUpdate: AgentTurnSessionUpdate;
}

type AgentTurnFailureCode = "agent.invalid_input" | "agent.provider_not_found" | "agent.turn_cancelled" | "agent.turn_timed_out";

type TimeoutHandle = ReturnType<typeof setTimeout>;

export interface AgentRunnerTimers {
  setTimeout(handler: () => void, timeoutMs: number): TimeoutHandle;
  clearTimeout(handle: TimeoutHandle): void;
}

export interface AgentRunnerOptions {
  defaultProviderTimeoutMs?: number;
  timers?: AgentRunnerTimers;
  turnQueue?: SessionTurnQueue;
}

type NormalizedAgentTurnInput = Required<Pick<AgentTurnInput, "content" | "providerName">> &
  Omit<AgentTurnInput, "content" | "providerName">;

export function createRuntimeContext(options: RuntimeContextOptions): RuntimeContext {
  const baseUtilities = options.utilities ?? createDefaultRuntimeUtilities();
  const utilities: RuntimeUtilities =
    options.clock === undefined && options.idGenerator === undefined
      ? baseUtilities
      : {
          ...baseUtilities,
          ...(options.clock !== undefined ? { clock: options.clock } : {}),
          ...(options.idGenerator !== undefined ? { idGenerator: options.idGenerator } : {})
        };
  const audit = options.audit ?? new InMemoryAuditSink();
  const auditContext = {
    audit,
    clock: utilities.clock,
    idGenerator: utilities.idGenerator
  };
  const filesystem =
    options.filesystem ??
    new FilesystemRootPolicy({
      roots: options.filesystemRoots ?? ["."]
    });
  const tools = options.tools ?? new ToolRegistry();
  if (options.tools === undefined) {
    registerEchoTool(tools);
    registerReadFileTool(tools, {
      filesystem
    });
    registerWriteFileTool(tools, {
      filesystem
    });
    registerWebFetchTool(tools);
  }
  const sessions =
    options.sessions ??
    new DirectorySessionStore({
      stateDirectory: options.config.stateDirectory,
      filesystem,
      policy: options.policy,
      audit,
      clock: utilities.clock,
      idGenerator: utilities.idGenerator
    });
  const transcripts =
    options.transcripts ??
    new DirectoryTranscriptStore({
      stateDirectory: options.config.stateDirectory,
      filesystem,
      policy: options.policy,
      audit,
      clock: utilities.clock,
      idGenerator: utilities.idGenerator
    });
  const eventBus = options.eventBus ?? new LocalRuntimeEventBus(options.logger);

  return {
    config: options.config,
    logger: options.logger,
    policy: options.policy,
    audit,
    tools,
    providers: options.providers ?? new ProviderRegistry(),
    memory: options.memory ?? new InMemoryStore(options.policy, auditContext),
    secrets: options.secrets ?? new EnvSecretStore(options.policy, auditContext, options.secretEnv ?? {}),
    sessions,
    transcripts,
    eventBus,
    filesystem,
    utilities,
    clock: utilities.clock,
    idGenerator: utilities.idGenerator
  };
}

export function createRuntimeDomainEvent<TType extends DomainEventType>(
  runtime: RuntimeContext,
  options: CreateDomainEventFromRuntimeOptions<TType>
): DomainEvent<TType> {
  return createDomainEventFromRuntime(runtime, options);
}

export async function emitRuntimeDomainEvent<TType extends DomainEventType>(
  runtime: RuntimeContext,
  options: CreateDomainEventFromRuntimeOptions<TType>
): Promise<DomainEvent<TType>> {
  const event = createRuntimeDomainEvent(runtime, options);
  await runtime.eventBus.emit(event);
  return event;
}

function agentError(code: AgentTurnFailureCode, message: string, context?: JsonObject): Result<never> {
  return err(
    new AppError({
      code,
      message,
      ...(context !== undefined ? { context } : {})
    })
  );
}

function validateTimeoutMs(timeoutMs: number | undefined): Result<number | undefined> {
  if (timeoutMs === undefined) {
    return ok(undefined);
  }

  if (!Number.isInteger(timeoutMs) || timeoutMs <= 0 || !Number.isFinite(timeoutMs)) {
    return agentError("agent.invalid_input", "Agent turn timeoutMs must be a positive integer when provided", {
      field: "timeoutMs"
    });
  }

  return ok(timeoutMs);
}

function normalizeAgentTurnInput(input: AgentTurnInput): Result<NormalizedAgentTurnInput> {
  const content = input.content.trim();
  if (content.length === 0) {
    return agentError("agent.invalid_input", "Agent turn content must be a non-empty string", {
      field: "content"
    });
  }

  return ok({
    ...input,
    content,
    providerName: input.providerName ?? providerName("mock")
  });
}

function transcriptEventToChatMessage(event: TranscriptEvent): ChatMessage | undefined {
  if (event.type !== "user" && event.type !== "assistant") {
    return undefined;
  }

  const message: ChatMessage = {
    role: event.type,
    content: event.payload.content
  };

  if (event.payload.metadata !== undefined) {
    message.metadata = event.payload.metadata;
  }

  return message;
}

function errorTranscriptPayload(error: unknown): TranscriptErrorPayload {
  const safeError = toAppError(error, {
    code: "unexpected",
    message: "Agent turn failed"
  });

  const payload: TranscriptErrorPayload = {
    errorName: safeError.name,
    message: safeError.message,
    code: safeError.code
  };

  if (safeError.context !== undefined) {
    payload.metadata = safeError.context;
  }

  return payload;
}

function assistantTranscriptPayload(response: ChatResponse): TranscriptAssistantPayload {
  const payload: TranscriptAssistantPayload = {
    content: response.message.content
  };

  if (response.message.metadata !== undefined) {
    payload.metadata = response.message.metadata;
  }

  return payload;
}

async function auditRunnerProviderCall(
  runtime: RuntimeContext,
  options: {
    decision: "allowed" | "denied" | "not_applicable" | "pending";
    messageCount?: number;
    model?: string | undefined;
    outcome: "requested" | "succeeded" | "failed" | "denied";
    providerName: ProviderName;
    sessionId: SessionId;
    error?: AppError;
  }
): Promise<void> {
  await appendAuditEvent(runtime, {
    sourcePackage: "@dominic-nexus/core",
    action:
      options.outcome === "requested"
        ? "provider.call_requested"
        : options.outcome === "succeeded"
          ? "provider.call_succeeded"
          : "provider.call_failed",
    decision: options.decision,
    sessionId: options.sessionId,
    resource: {
      type: "provider",
      id: options.providerName,
      name: options.providerName
    },
    outcome: options.outcome,
    metadata: {
      model: options.model ?? null,
      ...(options.messageCount !== undefined ? { messageCount: options.messageCount } : {}),
      ...(options.error !== undefined
        ? {
            errorCode: options.error.code,
            errorMessage: options.error.message
          }
        : {})
    }
  });
}

function logAgentTurnFailure(
  runtime: RuntimeContext,
  session: AgentSession,
  error: AppError,
  metadata: Record<string, JsonValue> = {}
): void {
  runtime.logger.warn("Agent turn failed", {
    sessionId: session.id,
    errorCode: error.code,
    errorMessage: error.message,
    ...metadata
  });
}

async function emitProviderCallRequested(
  runtime: RuntimeContext,
  options: {
    messageCount?: number;
    model?: string | undefined;
    providerName: ProviderName;
    sessionId: SessionId;
  }
): Promise<void> {
  await emitRuntimeDomainEvent(runtime, {
    type: "provider.call_requested",
    sourcePackage: "@dominic-nexus/core",
    sessionId: options.sessionId,
    payload: {
      providerName: options.providerName,
      ...(options.model !== undefined ? { model: options.model } : {}),
      ...(options.messageCount !== undefined ? { messageCount: options.messageCount } : {})
    }
  });
}

async function emitProviderCallSucceeded(
  runtime: RuntimeContext,
  options: {
    messageCount?: number;
    model?: string | undefined;
    providerName: ProviderName;
    sessionId: SessionId;
  }
): Promise<void> {
  await emitRuntimeDomainEvent(runtime, {
    type: "provider.call_succeeded",
    sourcePackage: "@dominic-nexus/core",
    sessionId: options.sessionId,
    payload: {
      providerName: options.providerName,
      ...(options.model !== undefined ? { model: options.model } : {}),
      ...(options.messageCount !== undefined ? { messageCount: options.messageCount } : {})
    }
  });
}

async function emitProviderCallFailed(
  runtime: RuntimeContext,
  options: {
    error: AppError;
    model?: string | undefined;
    providerName: ProviderName;
    sessionId: SessionId;
  }
): Promise<void> {
  await emitRuntimeDomainEvent(runtime, {
    type: "provider.call_failed",
    sourcePackage: "@dominic-nexus/core",
    sessionId: options.sessionId,
    payload: {
      providerName: options.providerName,
      errorCode: options.error.code,
      errorMessage: options.error.message,
      ...(options.model !== undefined ? { model: options.model } : {})
    }
  });
}

function createTurnCancelledError(providerName: ProviderName): AppError {
  return new AppError({
    code: "agent.turn_cancelled",
    message: `Agent turn cancelled before provider completed: ${providerName}`,
    context: {
      providerName
    }
  });
}

function createTurnTimedOutError(providerName: ProviderName, timeoutMs: number): AppError {
  return new AppError({
    code: "agent.turn_timed_out",
    message: `Agent turn timed out after ${timeoutMs}ms: ${providerName}`,
    context: {
      providerName,
      timeoutMs
    }
  });
}

function isTurnCancellationError(error: AppError): boolean {
  return error.code === "agent.turn_cancelled" || error.code === "agent.turn_timed_out";
}

function normalizeProviderExecutionError(error: AppError, providerName: ProviderName): AppError {
  if (error.code !== "provider.not_found") {
    return error;
  }

  return new AppError({
    code: "agent.provider_not_found",
    message: `Provider not found: ${providerName}`,
    context: {
      providerName
    }
  });
}

async function recordProviderTurnFailure(
  runtime: RuntimeContext,
  session: AgentSession,
  options: {
    error: AppError;
    messageCount: number;
    model?: string | undefined;
    phase: string;
    providerName: ProviderName;
  }
): Promise<Result<never>> {
  await auditRunnerProviderCall(runtime, {
    decision: options.error.code === "provider.permission_denied" ? "denied" : "not_applicable",
    error: options.error,
    messageCount: options.messageCount,
    model: options.model,
    outcome: options.error.code === "provider.permission_denied" ? "denied" : "failed",
    providerName: options.providerName,
    sessionId: session.id
  });
  await emitProviderCallFailed(runtime, {
    error: options.error,
    model: options.model,
    providerName: options.providerName,
    sessionId: session.id
  });
  logAgentTurnFailure(runtime, session, options.error, {
    phase: options.phase,
    providerName: options.providerName
  });
  await runtime.transcripts.append(session.id, {
    type: "error",
    payload: errorTranscriptPayload(options.error)
  });
  return err(options.error);
}

async function emitRuntimeFailure(
  runtime: RuntimeContext,
  sessionId: SessionId,
  error: AppError
): Promise<void> {
  await emitRuntimeDomainEvent(runtime, {
    type: "lifecycle.runtime_failed",
    sourcePackage: "@dominic-nexus/core",
    sessionId,
    payload: {
      errorCode: error.code,
      errorMessage: error.message
    }
  });
}

export class AgentRunner {
  private readonly defaultProviderTimeoutMs: number | undefined;
  private readonly timers: AgentRunnerTimers;
  private readonly turnQueue: SessionTurnQueue;

  constructor(options: AgentRunnerOptions = {}) {
    this.defaultProviderTimeoutMs = options.defaultProviderTimeoutMs;
    this.turnQueue = options.turnQueue ?? new SessionTurnQueue();
    this.timers = options.timers ?? {
      setTimeout: globalThis.setTimeout.bind(globalThis),
      clearTimeout: globalThis.clearTimeout.bind(globalThis)
    };
  }

  async runTurn(
    session: AgentSession,
    input: AgentTurnInput,
    options: AgentTurnOptions = {}
  ): Promise<Result<AgentTurnResponse>> {
    const normalized = normalizeAgentTurnInput(input);
    if (!normalized.ok) {
      return normalized;
    }

    const timeoutMs = validateTimeoutMs(options.timeoutMs ?? this.defaultProviderTimeoutMs);
    if (!timeoutMs.ok) {
      return timeoutMs;
    }

    const routingKey =
      options.sessionRoutingKey !== undefined ? ok(options.sessionRoutingKey) : createCliSessionRoutingKey({ sessionId: session.id });
    if (!routingKey.ok) {
      return routingKey;
    }

    return this.turnQueue.enqueue(routingKey.value, () =>
      this.runTurnNow(session, normalized.value, {
        ...(options.signal !== undefined ? { signal: options.signal } : {}),
        timeoutMs: timeoutMs.value
      })
    );
  }

  private async runTurnNow(
    session: AgentSession,
    input: NormalizedAgentTurnInput,
    options: {
      signal?: AbortSignal;
      timeoutMs?: number | undefined;
    }
  ): Promise<Result<AgentTurnResponse>> {
    const runtime = session.runtime;
    const lifecycleEvent = await runtime.transcripts.append(session.id, {
      type: "lifecycle",
      payload: {
        name: "turn.started",
        metadata: {
          providerName: input.providerName,
          model: input.model ?? null
        }
      }
    });
    if (!lifecycleEvent.ok) {
      logAgentTurnFailure(runtime, session, lifecycleEvent.error, {
        phase: "lifecycle.append"
      });
      await emitRuntimeFailure(runtime, session.id, lifecycleEvent.error);
      return lifecycleEvent;
    }

    const userEvent = await runtime.transcripts.append(session.id, {
      type: "user",
      payload: {
        content: input.content,
        ...(input.metadata !== undefined ? { metadata: input.metadata } : {})
      }
    });
    if (!userEvent.ok) {
      logAgentTurnFailure(runtime, session, userEvent.error, {
        phase: "user.append"
      });
      await emitRuntimeFailure(runtime, session.id, userEvent.error);
      return userEvent;
    }

    const transcript = await runtime.transcripts.read(session.id);
    if (!transcript.ok) {
      await auditRunnerProviderCall(runtime, {
        decision: "not_applicable",
        error: transcript.error,
        model: input.model,
        outcome: "failed",
        providerName: input.providerName,
        sessionId: session.id
      });
      await emitRuntimeFailure(runtime, session.id, transcript.error);
      logAgentTurnFailure(runtime, session, transcript.error, {
        phase: "transcript.read",
        providerName: input.providerName
      });
      await runtime.transcripts.append(session.id, {
        type: "error",
        payload: errorTranscriptPayload(transcript.error)
      });
      return transcript;
    }

    const messages = transcript.value.events
      .map((event) => transcriptEventToChatMessage(event))
      .filter((message): message is ChatMessage => message !== undefined);

    let response: ChatResponse;
    await auditRunnerProviderCall(runtime, {
      decision: "pending",
      messageCount: messages.length,
      model: input.model,
      outcome: "requested",
      providerName: input.providerName,
      sessionId: session.id
    });
    await emitProviderCallRequested(runtime, {
      messageCount: messages.length,
      model: input.model,
      providerName: input.providerName,
      sessionId: session.id
    });

    if (options.signal?.aborted === true) {
      return recordProviderTurnFailure(runtime, session, {
        error: createTurnCancelledError(input.providerName),
        messageCount: messages.length,
        model: input.model,
        phase: "provider.cancelled",
        providerName: input.providerName
      });
    }

    try {
      response = await this.runProviderChat({
        providerName: input.providerName,
        request: {
          messages,
          ...(input.model !== undefined ? { model: input.model } : {}),
          metadata: {
            ...(input.metadata ?? {}),
            sessionId: session.id
          }
        },
        execute: (request) =>
          runtime.providers.chatResult(input.providerName, request, {
            policy: runtime.policy,
            auditContext: {
              ...runtime,
              sessionId: session.id
            }
          }),
        ...(options.signal !== undefined ? { signal: options.signal } : {}),
        ...(options.timeoutMs !== undefined ? { timeoutMs: options.timeoutMs } : {})
      });
    } catch (error) {
      const appError = normalizeProviderExecutionError(
        toAppError(error, {
          code: "provider.execution_failed",
          message: `Provider execution failed: ${input.providerName}`,
          context: {
            providerName: input.providerName
          }
        }),
        input.providerName
      );
      return recordProviderTurnFailure(runtime, session, {
        error: appError,
        messageCount: messages.length,
        model: input.model,
        phase:
          appError.code === "agent.provider_not_found"
            ? "provider.lookup"
            : isTurnCancellationError(appError)
              ? "provider.cancelled"
              : "provider.chat",
        providerName: input.providerName
      });
    }
    await auditRunnerProviderCall(runtime, {
      decision: "allowed",
      messageCount: messages.length,
      model: input.model,
      outcome: "succeeded",
      providerName: input.providerName,
      sessionId: session.id
    });
    await emitProviderCallSucceeded(runtime, {
      messageCount: messages.length,
      model: input.model,
      providerName: input.providerName,
      sessionId: session.id
    });

    const assistantEvent = await runtime.transcripts.append(session.id, {
      type: "assistant",
      payload: assistantTranscriptPayload(response)
    });
    if (!assistantEvent.ok) {
      logAgentTurnFailure(runtime, session, assistantEvent.error, {
        phase: "assistant.append",
        providerName: input.providerName
      });
      await emitRuntimeFailure(runtime, session.id, assistantEvent.error);
      return assistantEvent;
    }

    const sessionUpdate = await this.touchSession(session);
    if (!sessionUpdate.ok) {
      logAgentTurnFailure(runtime, session, sessionUpdate.error, {
        phase: "session.touch",
        providerName: input.providerName
      });
      await emitRuntimeFailure(runtime, session.id, sessionUpdate.error);
      await runtime.transcripts.append(session.id, {
        type: "error",
        payload: errorTranscriptPayload(sessionUpdate.error)
      });
      return sessionUpdate;
    }

    return ok({
      content: response.message.content,
      message: response.message,
      providerName: input.providerName,
      ...(input.model !== undefined ? { model: input.model } : {}),
      transcriptEvents: {
        lifecycle: lifecycleEvent.value.eventId,
        user: userEvent.value.eventId,
        assistant: assistantEvent.value.eventId
      },
      sessionUpdate: sessionUpdate.value
    });
  }

  private async runProviderChat(options: {
    providerName: ProviderName;
    request: ChatRequest;
    execute(request: ChatRequest): Promise<Result<ChatResponse>>;
    signal?: AbortSignal;
    timeoutMs?: number | undefined;
  }): Promise<ChatResponse> {
    const controller = new AbortController();
    let timeoutHandle: TimeoutHandle | undefined;
    let settled = false;

    return new Promise<ChatResponse>((resolve, reject) => {
      const fail = (error: AppError): void => {
        if (settled) {
          return;
        }

        settled = true;
        cleanup();
        reject(error);
      };

      const cleanup = (): void => {
        if (timeoutHandle !== undefined) {
          this.timers.clearTimeout(timeoutHandle);
          timeoutHandle = undefined;
        }

        options.signal?.removeEventListener("abort", onCallerAbort);
      };

      const onCallerAbort = (): void => {
        controller.abort();
        fail(createTurnCancelledError(options.providerName));
      };

      const shouldPassAbortSignal = options.signal !== undefined || options.timeoutMs !== undefined;
      if (options.signal?.aborted === true) {
        fail(createTurnCancelledError(options.providerName));
        return;
      }

      options.signal?.addEventListener("abort", onCallerAbort, { once: true });

      const timeoutMs = options.timeoutMs;
      if (timeoutMs !== undefined) {
        timeoutHandle = this.timers.setTimeout(() => {
          controller.abort();
          fail(createTurnTimedOutError(options.providerName, timeoutMs));
        }, timeoutMs);
      }

      const providerPromise = Promise.resolve()
        .then(() =>
          options.execute({
            ...options.request,
            ...(shouldPassAbortSignal ? { signal: controller.signal } : {})
          })
        )
        .then(
          (result) => {
            if (settled) {
              return;
            }

            settled = true;
            cleanup();
            if (result.ok) {
              resolve(result.value);
              return;
            }

            reject(result.error);
          },
          (error: unknown) => {
            if (settled) {
              return;
            }

            settled = true;
            cleanup();
            reject(error);
          }
        );

      providerPromise.catch(() => undefined);
    });
  }

  private async touchSession(session: AgentSession): Promise<Result<AgentTurnSessionUpdate>> {
    const updated = await session.runtime.sessions.update(session.id, {
      touchInteraction: true
    });
    if (updated.ok) {
      session.metadata = updated.value.metadata;
      await emitRuntimeDomainEvent(session.runtime, {
        type: "session.updated",
        sourcePackage: "@dominic-nexus/core",
        sessionId: session.id,
        payload: {
          reason: "turn.completed"
        }
      });
      return ok({
        persisted: true,
        metadata: updated.value.metadata
      });
    }

    if (updated.error.code === "session.not_found") {
      return ok({
        persisted: false
      });
    }

    return err(updated.error);
  }
}

export function createAgentSession(runtime: RuntimeContext): AgentSession {
  const now = runtime.clock.nowIso();
  return {
    id: runtime.idGenerator.createSessionId(),
    agentId: agentId("agent-default"),
    runtime,
    metadata: {
      sessionStartedAt: now,
      lastInteractionAt: null,
      updatedAt: now,
      attributes: {}
    }
  };
}

export async function startRuntime(runtime: RuntimeContext, session?: AgentSession): Promise<void> {
  runtime.logger.info("Runtime started", {
    appName: runtime.config.appName,
    environment: runtime.config.environment,
    sessionId: session?.id ?? null
  });
  await emitRuntimeDomainEvent(runtime, {
    type: "lifecycle.runtime_started",
    sourcePackage: "@dominic-nexus/core",
    ...(session !== undefined ? { sessionId: session.id } : {}),
    payload: {
      appName: runtime.config.appName,
      environment: runtime.config.environment
    }
  });
}
