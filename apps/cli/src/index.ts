#!/usr/bin/env node
import { loadConfig } from "@dominic-nexus/config";
import { createAgentSession, createRuntimeContext, startRuntime } from "@dominic-nexus/core";
import { createConsoleLogger } from "@dominic-nexus/logging";
import { AllowAllDevelopmentPolicy } from "@dominic-nexus/permissions";
import { MockProvider } from "@dominic-nexus/providers";
import { runChatLoop } from "./chat.js";

const config = loadConfig();
const logger = createConsoleLogger();
const policy = new AllowAllDevelopmentPolicy();
const runtime = createRuntimeContext({ config, logger, policy });
const session = createAgentSession(runtime);
const provider = new MockProvider(policy);

runtime.providers.register(provider);

await startRuntime(runtime, session);
await runChatLoop({
  input: process.stdin,
  output: process.stdout,
  session,
  provider,
  logger
});
