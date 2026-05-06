import type { PermissionRequest, PolicyEngine } from "@dominic-nexus/permissions";
import type { JsonValue } from "@dominic-nexus/shared";

export type ChatRole = "system" | "user" | "assistant" | "tool";

export interface ChatMessage {
  role: ChatRole;
  content: string;
  metadata?: Record<string, JsonValue>;
}

export interface ChatRequest {
  messages: ChatMessage[];
  model?: string;
  metadata?: Record<string, JsonValue>;
}

export interface ChatResponse {
  message: ChatMessage;
  metadata?: Record<string, JsonValue>;
}

export interface ModelProvider {
  name: string;
  chat(request: ChatRequest): Promise<ChatResponse>;
}

export class ProviderRegistry {
  private readonly providers = new Map<string, ModelProvider>();

  register(provider: ModelProvider): void {
    this.providers.set(provider.name, provider);
  }

  get(name: string): ModelProvider | undefined {
    return this.providers.get(name);
  }
}

export class MockProvider implements ModelProvider {
  readonly name = "mock";

  constructor(private readonly policy: PolicyEngine) {}

  async chat(request: ChatRequest): Promise<ChatResponse> {
    const permissionRequest: PermissionRequest = {
      action: "provider.call",
      reason: "Call mock model provider",
      resource: this.name
    };

    if (request.metadata !== undefined) {
      permissionRequest.metadata = request.metadata;
    }

    const decision = await this.policy.decide(permissionRequest);

    if (!decision.allowed) {
      throw new Error(decision.reason);
    }

    const lastUserMessage = [...request.messages].reverse().find((message) => message.role === "user");
    return {
      message: {
        role: "assistant",
        content: lastUserMessage?.content ?? "Mock provider response."
      }
    };
  }
}
