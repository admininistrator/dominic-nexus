import { randomUUID } from "node:crypto";
import type { PolicyEngine } from "@dominic-nexus/permissions";
import type { JsonValue, ISODateTimeString } from "@dominic-nexus/shared";

export interface MemoryRecord {
  id: string;
  namespace: string;
  content: JsonValue;
  createdAt: ISODateTimeString;
  updatedAt: ISODateTimeString;
  metadata?: Record<string, JsonValue>;
}

export interface MemoryStore {
  write(record: Omit<MemoryRecord, "id" | "createdAt" | "updatedAt">): Promise<MemoryRecord>;
  search(namespace: string): Promise<MemoryRecord[]>;
}

export class InMemoryStore implements MemoryStore {
  private readonly records = new Map<string, MemoryRecord>();

  constructor(private readonly policy: PolicyEngine) {}

  async write(record: Omit<MemoryRecord, "id" | "createdAt" | "updatedAt">): Promise<MemoryRecord> {
    const decision = await this.policy.decide({
      action: "memory.write",
      reason: "Write memory record",
      resource: record.namespace
    });

    if (!decision.allowed) {
      throw new Error(decision.reason);
    }

    const now = new Date().toISOString();
    const stored: MemoryRecord = {
      id: randomUUID(),
      namespace: record.namespace,
      content: record.content,
      createdAt: now,
      updatedAt: now
    };

    if (record.metadata !== undefined) {
      stored.metadata = record.metadata;
    }

    this.records.set(stored.id, stored);
    return stored;
  }

  async search(namespace: string): Promise<MemoryRecord[]> {
    const decision = await this.policy.decide({
      action: "memory.read",
      reason: "Search memory records",
      resource: namespace
    });

    if (!decision.allowed) {
      throw new Error(decision.reason);
    }

    return [...this.records.values()].filter((record) => record.namespace === namespace);
  }
}
