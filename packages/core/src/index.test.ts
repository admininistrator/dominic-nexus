import { afterEach, describe, expect, it, vi } from "vitest";
import type { AppConfig } from "@dominic-nexus/config";
import type { Logger } from "@dominic-nexus/logging";
import { AllowAllDevelopmentPolicy } from "@dominic-nexus/permissions";
import { ProviderRegistry } from "@dominic-nexus/providers";
import { ToolRegistry } from "@dominic-nexus/tools";
import { createAgentSession, createRuntimeContext } from "./index.js";

const config: AppConfig = {
  appName: "Test Nexus",
  environment: "test",
  logLevel: "info"
};

const logger: Logger = {
  debug: vi.fn(),
  info: vi.fn(),
  warn: vi.fn(),
  error: vi.fn()
};

afterEach(() => {
  vi.restoreAllMocks();
});

describe("createRuntimeContext", () => {
  it("creates registries and registers the echo tool", async () => {
    const policy = new AllowAllDevelopmentPolicy();
    const runtime = createRuntimeContext({ config, logger, policy });

    expect(runtime.config).toBe(config);
    expect(runtime.logger).toBe(logger);
    expect(runtime.policy).toBe(policy);
    expect(runtime.tools).toBeInstanceOf(ToolRegistry);
    expect(runtime.providers).toBeInstanceOf(ProviderRegistry);
    await expect(runtime.tools.execute("echo", "hello", { policy })).resolves.toBe("hello");
  });
});

describe("createAgentSession", () => {
  it("creates a deterministic session id from Date.now and attaches runtime", () => {
    vi.spyOn(Date, "now").mockReturnValue(12345);
    const runtime = createRuntimeContext({
      config,
      logger,
      policy: new AllowAllDevelopmentPolicy()
    });

    const session = createAgentSession(runtime);

    expect(session).toEqual({
      id: "session-12345",
      runtime,
      metadata: {}
    });
  });
});
