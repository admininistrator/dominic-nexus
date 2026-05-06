import type { JsonValue } from "@dominic-nexus/shared";

export type PermissionAction =
  | "filesystem.read"
  | "filesystem.write"
  | "shell.execute"
  | "network.request"
  | "secret.read"
  | "memory.read"
  | "memory.write"
  | "plugin.execute"
  | "provider.call";

export interface PermissionRequest {
  action: PermissionAction;
  reason: string;
  resource?: string;
  metadata?: Record<string, JsonValue>;
}

export type PermissionDecision =
  | {
      allowed: true;
      reason?: string;
    }
  | {
      allowed: false;
      reason: string;
    };

export interface PolicyEngine {
  decide(request: PermissionRequest): PermissionDecision | Promise<PermissionDecision>;
}

export class DefaultDenyPolicy implements PolicyEngine {
  decide(request: PermissionRequest): PermissionDecision {
    return {
      allowed: false,
      reason: `Denied by default policy: ${request.action}`
    };
  }
}

export class AllowAllDevelopmentPolicy implements PolicyEngine {
  decide(): PermissionDecision {
    return {
      allowed: true,
      reason: "Allowed by development policy"
    };
  }
}
