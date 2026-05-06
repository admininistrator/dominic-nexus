import { describe, expect, it, vi } from "vitest";
import type { AgentSession, RuntimeContext } from "@dominic-nexus/core";
import type { Logger } from "@dominic-nexus/logging";
import type { ChatRequest, ChatResponse, ModelProvider } from "@dominic-nexus/providers";
import { createChatLoopState, handleChatInput } from "./chat.js";

function createLogger(): Logger {
  return {
    debug: vi.fn(),
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn()
  };
}

function createSession(): AgentSession {
  return {
    id: "session-test",
    runtime: {} as RuntimeContext,
    metadata: {}
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
  const provider: ModelProvider = {
    name: "test-provider",
    async chat(request) {
      requests.push(request);
      return response;
    }
  };

  return {
    provider,
    requests
  };
}

describe("handleChatInput", () => {
  it("ignores empty input without calling the provider", async () => {
    const state = createChatLoopState();
    const logger = createLogger();
    const { output, lines } = createOutput();
    const { provider, requests } = createProvider();

    await expect(
      handleChatInput({
        line: "   ",
        session: createSession(),
        provider,
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
    const { provider, requests } = createProvider();

    await expect(
      handleChatInput({
        line: "/exit",
        session: createSession(),
        provider,
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
    const { provider, requests } = createProvider({
      message: {
        role: "assistant",
        content: "hello back"
      }
    });

    await expect(
      handleChatInput({
        line: " hello ",
        session: createSession(),
        provider,
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
});
