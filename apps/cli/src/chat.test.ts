import { describe, expect, it, vi } from "vitest";
import type { AgentSession, RuntimeContext } from "@dominic-nexus/core";
import type { Logger } from "@dominic-nexus/logging";
import { AllowAllDevelopmentPolicy, InteractiveApprovalPolicy, type PolicyEngine } from "@dominic-nexus/permissions";
import { MockProvider, ProviderRegistry, type ChatRequest, type ChatResponse, type ModelProvider } from "@dominic-nexus/providers";
import { agentId, providerName, sessionId } from "@dominic-nexus/shared";
import { createChatLoopState, handleChatInput } from "./chat.js";

function createLogger(): Logger {
  return {
    debug: vi.fn(),
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn()
  };
}

function createSession(policy: PolicyEngine = new AllowAllDevelopmentPolicy()): AgentSession {
  return {
    id: sessionId("session-test"),
    agentId: agentId("agent-test"),
    runtime: {
      policy
    } as unknown as RuntimeContext,
    metadata: {
      sessionStartedAt: "2026-05-10T00:00:00.000Z",
      lastInteractionAt: null,
      updatedAt: "2026-05-10T00:00:00.000Z",
      attributes: {}
    }
  };
}

function createOutput() {
  const lines: string[] = [];

  return {
    lines,
    output: {
      writeLine(line: string) {
        lines.push(line);
      }
    }
  };
}

function createProvider(response: ChatResponse = { message: { role: "assistant", content: "mock reply" } }) {
  const requests: ChatRequest[] = [];
  const registry = new ProviderRegistry();
  const provider: ModelProvider = {
    name: providerName("test-provider"),
    capabilities: {
      chat: true,
      modelListing: false
    },
    async chat(request) {
      requests.push(request);
      return response;
    }
  };
  registry.register(provider);

  return {
    providers: registry,
    providerName: provider.name,
    requests
  };
}

function createInteractiveMockProvider(answer: string) {
  const prompts: unknown[] = [];
  const policy = new InteractiveApprovalPolicy({
    prompt(request) {
      prompts.push(request);
      return answer;
    }
  });

  return {
    providers: (() => {
      const registry = new ProviderRegistry();
      registry.register(new MockProvider(policy));
      return registry;
    })(),
    providerName: providerName("mock"),
    policy,
    prompts
  };
}

describe("handleChatInput", () => {
  it("ignores empty input without calling the provider", async () => {
    const state = createChatLoopState();
    const logger = createLogger();
    const { output, lines } = createOutput();
    const { providers, providerName, requests } = createProvider();

    await expect(
      handleChatInput({
        line: "   ",
        session: createSession(),
        providers,
        providerName,
        logger,
        output,
        state
      })
    ).resolves.toBe("continue");

    expect(requests).toEqual([]);
    expect(lines).toEqual([]);
    expect(state.messages).toEqual([]);
    expect(logger.info).not.toHaveBeenCalled();
  });

  it("exits cleanly on /exit", async () => {
    const state = createChatLoopState();
    const logger = createLogger();
    const { output, lines } = createOutput();
    const { providers, providerName, requests } = createProvider();

    await expect(
      handleChatInput({
        line: "/exit",
        session: createSession(),
        providers,
        providerName,
        logger,
        output,
        state
      })
    ).resolves.toBe("exit");

    expect(requests).toEqual([]);
    expect(lines).toEqual(["Goodbye."]);
    expect(logger.info).toHaveBeenCalledWith("CLI chat session ended", {
      sessionId: "session-test"
    });
  });

  it("sends user input to the provider and prints the assistant response", async () => {
    const state = createChatLoopState();
    const logger = createLogger();
    const { output, lines } = createOutput();
    const { providers, providerName, requests } = createProvider({
      message: {
        role: "assistant",
        content: "hello back"
      }
    });

    await expect(
      handleChatInput({
        line: " hello ",
        session: createSession(),
        providers,
        providerName,
        logger,
        output,
        state
      })
    ).resolves.toBe("continue");

    expect(requests).toEqual([
      {
        messages: [
          {
            role: "user",
            content: "hello"
          }
        ],
        metadata: {
          sessionId: "session-test"
        }
      }
    ]);
    expect(state.messages).toEqual([
      {
        role: "user",
        content: "hello"
      },
      {
        role: "assistant",
        content: "hello back"
      }
    ]);
    expect(lines).toEqual(["Assistant: hello back"]);
    expect(logger.info).toHaveBeenCalledWith("CLI user message received", {
      sessionId: "session-test",
      messageLength: 5
    });
    expect(logger.info).toHaveBeenCalledWith("CLI assistant response sent", {
      sessionId: "session-test",
      messageLength: 10
    });
  });

  it("requires approval before CLI provider calls", async () => {
    const state = createChatLoopState();
    const logger = createLogger();
    const { output, lines } = createOutput();
    const { providers, providerName, policy, prompts } = createInteractiveMockProvider("yes");

    await expect(
      handleChatInput({
        line: "approve this",
        session: createSession(policy),
        providers,
        providerName,
        logger,
        output,
        state
      })
    ).resolves.toBe("continue");

    expect(prompts).toEqual([
      {
        action: "provider.call",
        reason: "Call mock model provider",
        resource: "mock"
      }
    ]);
    expect(lines).toEqual(["Assistant: approve this"]);
    expect(state.messages).toEqual([
      {
        role: "user",
        content: "approve this"
      },
      {
        role: "assistant",
        content: "approve this"
      }
    ]);
  });

  it("shows denied approvals without crashing or committing chat history", async () => {
    const state = createChatLoopState();
    const logger = createLogger();
    const { output, lines } = createOutput();
    const { providers, providerName, policy } = createInteractiveMockProvider("no");

    await expect(
      handleChatInput({
        line: "deny this",
        session: createSession(policy),
        providers,
        providerName,
        logger,
        output,
        state
      })
    ).resolves.toBe("continue");

    expect(lines).toEqual(["Error: Provider permission denied: mock"]);
    expect(state.messages).toEqual([]);
    expect(logger.warn).toHaveBeenCalledWith("CLI provider call failed", {
      sessionId: "session-test",
      errorCode: "provider.permission_denied",
      errorMessage: "Provider permission denied: mock"
    });
  });

  it("denies invalid approval answers without crashing or committing chat history", async () => {
    const state = createChatLoopState();
    const logger = createLogger();
    const { output, lines } = createOutput();
    const { providers, providerName, policy } = createInteractiveMockProvider("maybe");

    await expect(
      handleChatInput({
        line: "invalid answer",
        session: createSession(policy),
        providers,
        providerName,
        logger,
        output,
        state
      })
    ).resolves.toBe("continue");

    expect(lines).toEqual(["Error: Provider permission denied: mock"]);
    expect(state.messages).toEqual([]);
    expect(logger.warn).toHaveBeenCalledWith("CLI provider call failed", {
      sessionId: "session-test",
      errorCode: "provider.permission_denied",
      errorMessage: "Provider permission denied: mock"
    });
  });
});
