#!/usr/bin/env node
import { loadConfig } from "@dominic-nexus/config";
import { createAgentSession, createRuntimeContext, startRuntime } from "@dominic-nexus/core";
import { createConsoleLogger } from "@dominic-nexus/logging";
import { InteractiveApprovalPolicy, type ApprovalPromptRequest } from "@dominic-nexus/permissions";
import { MockProvider } from "@dominic-nexus/providers";
import { createChatQuestioner, runChatLoop } from "./chat.js";

function formatApprovalPrompt(request: ApprovalPromptRequest): string {
  const resource =
    request.resource === undefined
      ? ""
      : request.action === "secret.read"
        ? " resource=[secret reference hidden]"
        : ` resource=${request.resource}`;

  return `Allow ${request.action}? reason="${request.reason}"${resource} [y/N] `;
}

const config = loadConfig();
const logger = createConsoleLogger();
const questioner = createChatQuestioner({
  input: process.stdin,
  output: process.stdout
});
const policy = new InteractiveApprovalPolicy({
  prompt(request) {
    return questioner.question(formatApprovalPrompt(request));
  }
});
const runtime = createRuntimeContext({ config, logger, policy });
const session = createAgentSession(runtime);
const provider = new MockProvider(policy, {
  audit: runtime.audit,
  clock: runtime.clock,
  idGenerator: runtime.idGenerator,
  sessionId: session.id
});

runtime.providers.register(provider);

await startRuntime(runtime, session);
await runChatLoop({
  input: process.stdin,
  output: process.stdout,
  session,
  providers: runtime.providers,
  providerName: provider.name,
  logger,
  questioner
});
