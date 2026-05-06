#!/usr/bin/env node
import { loadConfig } from "@dominic-nexus/config";
import { createAgentSession, createRuntimeContext, startRuntime } from "@dominic-nexus/core";
import { createConsoleLogger } from "@dominic-nexus/logging";
import { AllowAllDevelopmentPolicy } from "@dominic-nexus/permissions";

const config = loadConfig();
const logger = createConsoleLogger();
const policy = new AllowAllDevelopmentPolicy();
const runtime = createRuntimeContext({ config, logger, policy });
const session = createAgentSession(runtime);

await startRuntime(runtime, session);

console.log("Dominic Nexus CLI is running.");
