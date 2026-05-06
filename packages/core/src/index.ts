import type { AppConfig } from "@dominic-nexus/config";
import type { Logger } from "@dominic-nexus/logging";
import type { PolicyEngine } from "@dominic-nexus/permissions";
import { ProviderRegistry } from "@dominic-nexus/providers";
import { echoTool, ToolRegistry } from "@dominic-nexus/tools";
import type { JsonValue } from "@dominic-nexus/shared";

export interface RuntimeContext {
  config: AppConfig;
  logger: Logger;
  policy: PolicyEngine;
  tools: ToolRegistry;
  providers: ProviderRegistry;
}

export interface RuntimeContextOptions {
  config: AppConfig;
  logger: Logger;
  policy: PolicyEngine;
}

export interface AgentSession {
  id: string;
  runtime: RuntimeContext;
  metadata: Record<string, JsonValue>;
}

export function createRuntimeContext(options: RuntimeContextOptions): RuntimeContext {
  const tools = new ToolRegistry();
  tools.register(echoTool);

  return {
    config: options.config,
    logger: options.logger,
    policy: options.policy,
    tools,
    providers: new ProviderRegistry()
  };
}

export function createAgentSession(runtime: RuntimeContext): AgentSession {
  return {
    id: `session-${Date.now()}`,
    runtime,
    metadata: {}
  };
}

export async function startRuntime(runtime: RuntimeContext, session?: AgentSession): Promise<void> {
  runtime.logger.info("Runtime started", {
    appName: runtime.config.appName,
    environment: runtime.config.environment,
    sessionId: session?.id ?? null
  });
}
