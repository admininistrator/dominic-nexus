import type { PermissionAction, PermissionRequest, PolicyEngine } from "@dominic-nexus/permissions";
import type { JsonValue } from "@dominic-nexus/shared";

export interface ToolExecutionContext {
  policy: PolicyEngine;
  metadata?: Record<string, JsonValue>;
}

export interface ToolDefinition<Input = unknown, Output = unknown> {
  name: string;
  description: string;
  requiredPermissions: PermissionAction[];
  execute(input: Input, context: ToolExecutionContext): Promise<Output> | Output;
}

export class ToolRegistry {
  private readonly tools = new Map<string, ToolDefinition>();

  register(tool: ToolDefinition): void {
    this.tools.set(tool.name, tool);
  }

  get(name: string): ToolDefinition | undefined {
    return this.tools.get(name);
  }

  async execute<Input, Output>(
    name: string,
    input: Input,
    context: ToolExecutionContext
  ): Promise<Output> {
    const tool = this.tools.get(name) as ToolDefinition<Input, Output> | undefined;

    if (tool === undefined) {
      throw new Error(`Tool not found: ${name}`);
    }

    for (const permission of tool.requiredPermissions) {
      const request: PermissionRequest = {
        action: permission,
        reason: `Execute tool: ${tool.name}`,
        resource: tool.name
      };

      if (context.metadata !== undefined) {
        request.metadata = context.metadata;
      }

      const decision = await context.policy.decide(request);

      if (!decision.allowed) {
        throw new Error(decision.reason);
      }
    }

    return tool.execute(input, context);
  }
}

export const echoTool: ToolDefinition<JsonValue, JsonValue> = {
  name: "echo",
  description: "Returns the provided input.",
  requiredPermissions: [],
  execute(input) {
    return input;
  }
};
