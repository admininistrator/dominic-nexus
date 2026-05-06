import type { Channel } from "@dominic-nexus/channels";
import type { ModelProvider } from "@dominic-nexus/providers";
import type { JsonValue } from "@dominic-nexus/shared";
import type { ToolDefinition } from "@dominic-nexus/tools";

export interface PluginManifest {
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

export interface DominicNexusPlugin {
  manifest: PluginManifest;
  tools?: ToolDefinition[];
  channels?: Channel[];
  providers?: ModelProvider[];
  setup?(context: PluginRuntimeContext): Promise<void> | void;
}
