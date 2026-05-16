import type { ChannelId, JsonValue, PluginId, ProviderName, ToolName } from "@dominic-nexus/shared";

export interface PluginManifest {
  id: PluginId;
  name: string;
  version: string;
  description?: string;
  permissions?: string[];
  metadata?: Record<string, JsonValue>;
}

export interface PluginRuntimeContext {
  manifest: PluginManifest;
  settings?: Record<string, JsonValue>;
}

export interface PluginToolExecutionContext {
  metadata?: Record<string, JsonValue>;
}

export interface PluginToolDefinition<Input = unknown, Output = unknown> {
  name: ToolName;
  description: string;
  requiredPermissions: string[];
  execute(input: Input, context: PluginToolExecutionContext): Promise<Output> | Output;
}

export type PluginChatRole = "system" | "user" | "assistant" | "tool";

export interface PluginChatMessage {
  role: PluginChatRole;
  content: string;
  metadata?: Record<string, JsonValue>;
}

export interface PluginChatRequest {
  messages: PluginChatMessage[];
  model?: string;
  metadata?: Record<string, JsonValue>;
}

export interface PluginChatResponse {
  message: PluginChatMessage;
  metadata?: Record<string, JsonValue>;
}

export interface PluginModelProvider {
  name: ProviderName;
  chat(request: PluginChatRequest): Promise<PluginChatResponse>;
}

export interface PluginChannelMessage {
  id: string;
  channelName: ChannelId;
  authorId: string;
  content: string;
  metadata?: Record<string, JsonValue>;
}

export interface PluginChannelSendRequest {
  channelName: ChannelId;
  content: string;
  metadata?: Record<string, JsonValue>;
}

export interface PluginChannel {
  name: ChannelId;
  send(request: PluginChannelSendRequest): Promise<PluginChannelMessage>;
}

export interface DominicNexusPlugin {
  manifest: PluginManifest;
  tools?: PluginToolDefinition[];
  channels?: PluginChannel[];
  providers?: PluginModelProvider[];
  setup?(context: PluginRuntimeContext): Promise<void> | void;
}
