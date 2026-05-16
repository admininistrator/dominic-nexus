import type { Logger } from "@dominic-nexus/logging";
import type { DomainEvent } from "@dominic-nexus/shared";

export type RuntimeEventSubscriber = (event: DomainEvent) => void | Promise<void>;

export interface RuntimeEventSubscription {
  unsubscribe(): void;
}

export interface RuntimeEventBus {
  emit(event: DomainEvent): Promise<void>;
  subscribe(subscriber: RuntimeEventSubscriber): RuntimeEventSubscription;
}

function cloneDomainEvent<TEvent extends DomainEvent>(event: TEvent): TEvent {
  return JSON.parse(JSON.stringify(event)) as TEvent;
}

function deepFreeze<TValue>(value: TValue): TValue {
  if (value === null || typeof value !== "object") {
    return value;
  }

  Object.freeze(value);

  for (const nested of Object.values(value)) {
    deepFreeze(nested);
  }

  return value;
}

function eventSnapshot<TEvent extends DomainEvent>(event: TEvent): TEvent {
  return deepFreeze(cloneDomainEvent(event));
}

export class LocalRuntimeEventBus implements RuntimeEventBus {
  private readonly subscribers = new Set<RuntimeEventSubscriber>();

  constructor(private readonly logger?: Logger) {}

  subscribe(subscriber: RuntimeEventSubscriber): RuntimeEventSubscription {
    this.subscribers.add(subscriber);

    return {
      unsubscribe: () => {
        this.subscribers.delete(subscriber);
      }
    };
  }

  async emit(event: DomainEvent): Promise<void> {
    for (const subscriber of this.subscribers) {
      try {
        await subscriber(eventSnapshot(event));
      } catch (error) {
        this.logger?.warn("Runtime event subscriber failed", {
          eventId: event.eventId,
          eventType: event.type,
          sourcePackage: event.sourcePackage,
          errorName: error instanceof Error ? error.name : "UnknownError"
        });
      }
    }
  }
}

export class RecordingRuntimeEventSubscriber {
  private readonly events: DomainEvent[] = [];

  handle: RuntimeEventSubscriber = (event) => {
    this.events.push(eventSnapshot(event));
  };

  listEvents(): readonly DomainEvent[] {
    return this.events.map((event) => eventSnapshot(event));
  }

  count(): number {
    return this.events.length;
  }
}
