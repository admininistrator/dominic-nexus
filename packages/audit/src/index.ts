import { redactLogContext } from "@dominic-nexus/logging";
import {
  assertJsonObject,
  type Clock,
  type EventId,
  type IdGenerator,
  type ISODateTimeString,
  type JsonObject,
  type RuntimeUtilities,
  type SessionId,
  type SourcePackage
} from "@dominic-nexus/shared";

export type AuditDecision = "allowed" | "denied" | "not_applicable" | "pending";
export type AuditOutcome = "requested" | "succeeded" | "failed" | "denied";

export interface AuditActor {
  type: "local_operator" | "system" | "channel_sender" | "plugin";
  id?: string;
  displayName?: string;
  metadata?: JsonObject;
}

export interface AuditResource {
  type: string;
  id?: string;
  name?: string;
  metadata?: JsonObject;
}

export interface AuditEvent {
  eventId: EventId;
  timestamp: ISODateTimeString;
  sourcePackage: SourcePackage;
  action: string;
  decision: AuditDecision;
  sessionId?: SessionId;
  actor?: AuditActor;
  resource?: AuditResource;
  outcome?: AuditOutcome;
  metadata?: JsonObject;
}

export interface CreateAuditEventOptions {
  eventId: EventId;
  timestamp: ISODateTimeString;
  sourcePackage: SourcePackage;
  action: string;
  decision: AuditDecision;
  sessionId?: SessionId;
  actor?: AuditActor;
  resource?: AuditResource;
  outcome?: AuditOutcome;
  metadata?: Record<string, unknown>;
}

export type CreateAuditEventFromRuntimeOptions = Omit<CreateAuditEventOptions, "eventId" | "timestamp">;

export interface AuditSink {
  append(event: AuditEvent): Promise<void>;
}

export interface AuditRuntimeContext {
  audit: AuditSink;
  clock: Clock;
  idGenerator: IdGenerator;
  sessionId?: SessionId;
  actor?: AuditActor;
}

export type OptionalAuditRuntimeContext = Partial<AuditRuntimeContext>;

function requireNonEmpty(value: string, label: string): string {
  if (value.trim().length === 0) {
    throw new Error(`${label} must be a non-empty string`);
  }

  return value;
}

export function redactAuditMetadata(metadata: Record<string, unknown>): JsonObject {
  const redacted = redactLogContext(metadata);
  assertJsonObject(redacted, "audit metadata");
  return redacted;
}

function redactAuditActor(actor: AuditActor): AuditActor {
  const redacted: AuditActor = {
    type: actor.type
  };

  if (actor.id !== undefined) {
    redacted.id = actor.id;
  }

  if (actor.displayName !== undefined) {
    redacted.displayName = actor.displayName;
  }

  if (actor.metadata !== undefined) {
    redacted.metadata = redactAuditMetadata(actor.metadata);
  }

  return redacted;
}

function redactAuditResource(resource: AuditResource): AuditResource {
  const redacted: AuditResource = {
    type: requireNonEmpty(resource.type, "audit resource type")
  };

  if (resource.id !== undefined) {
    redacted.id = resource.id;
  }

  if (resource.name !== undefined) {
    redacted.name = resource.name;
  }

  if (resource.metadata !== undefined) {
    redacted.metadata = redactAuditMetadata(resource.metadata);
  }

  return redacted;
}

export function createAuditEvent(options: CreateAuditEventOptions): AuditEvent {
  const event: AuditEvent = {
    eventId: options.eventId,
    timestamp: options.timestamp,
    sourcePackage: options.sourcePackage,
    action: requireNonEmpty(options.action, "audit action"),
    decision: options.decision
  };

  if (options.sessionId !== undefined) {
    event.sessionId = options.sessionId;
  }

  if (options.actor !== undefined) {
    event.actor = redactAuditActor(options.actor);
  }

  if (options.resource !== undefined) {
    event.resource = redactAuditResource(options.resource);
  }

  if (options.outcome !== undefined) {
    event.outcome = options.outcome;
  }

  if (options.metadata !== undefined) {
    event.metadata = redactAuditMetadata(options.metadata);
  }

  return serializeAuditEvent(event);
}

export function createAuditEventFromRuntime(
  utilities: RuntimeUtilities,
  options: CreateAuditEventFromRuntimeOptions
): AuditEvent {
  return createAuditEvent({
    ...options,
    eventId: utilities.idGenerator.createEventId(),
    timestamp: utilities.clock.nowIso()
  });
}

export async function appendAuditEvent(
  context: OptionalAuditRuntimeContext | undefined,
  options: CreateAuditEventFromRuntimeOptions
): Promise<void> {
  if (context?.audit === undefined || context.clock === undefined || context.idGenerator === undefined) {
    return;
  }

  const eventOptions: CreateAuditEventFromRuntimeOptions = {
    ...options
  };
  const sessionId = options.sessionId ?? context.sessionId;
  const actor = options.actor ?? context.actor;

  if (sessionId !== undefined) {
    eventOptions.sessionId = sessionId;
  }

  if (actor !== undefined) {
    eventOptions.actor = actor;
  }

  await context.audit.append(
    createAuditEventFromRuntime(
      {
        clock: context.clock,
        idGenerator: context.idGenerator
      },
      eventOptions
    )
  );
}

export function serializeAuditEvent(event: AuditEvent): AuditEvent {
  const serialized: AuditEvent = {
    eventId: event.eventId,
    timestamp: event.timestamp,
    sourcePackage: event.sourcePackage,
    action: requireNonEmpty(event.action, "audit action"),
    decision: event.decision
  };

  if (event.sessionId !== undefined) {
    serialized.sessionId = event.sessionId;
  }

  if (event.actor !== undefined) {
    serialized.actor = redactAuditActor(event.actor);
  }

  if (event.resource !== undefined) {
    serialized.resource = redactAuditResource(event.resource);
  }

  if (event.outcome !== undefined) {
    serialized.outcome = event.outcome;
  }

  if (event.metadata !== undefined) {
    serialized.metadata = redactAuditMetadata(event.metadata);
  }

  return JSON.parse(JSON.stringify(serialized)) as AuditEvent;
}

export class InMemoryAuditSink implements AuditSink {
  private readonly events: AuditEvent[] = [];

  async append(event: AuditEvent): Promise<void> {
    this.events.push(serializeAuditEvent(event));
  }

  listEvents(): readonly AuditEvent[] {
    return this.events.map((event) => serializeAuditEvent(event));
  }

  count(): number {
    return this.events.length;
  }
}
