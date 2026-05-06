import { createInterface } from "node:readline/promises";
import type { AgentSession } from "@dominic-nexus/core";
import type { Logger } from "@dominic-nexus/logging";
import type { ChatMessage, ModelProvider } from "@dominic-nexus/providers";

export interface ChatLoopState {
  messages: ChatMessage[];
}

export interface ChatOutput {
  writeLine(line: string): void;
}

export type ChatInputResult = "continue" | "exit";

export interface HandleChatInputOptions {
  line: string;
  session: AgentSession;
  provider: ModelProvider;
  logger: Logger;
  output: ChatOutput;
  state: ChatLoopState;
}

export interface RunChatLoopOptions {
  input: NodeJS.ReadableStream & {
    isTTY?: boolean;
  };
  output: NodeJS.WritableStream & {
    isTTY?: boolean;
  };
  session: AgentSession;
  provider: ModelProvider;
  logger: Logger;
}

export function createChatLoopState(): ChatLoopState {
  return {
    messages: []
  };
}

export async function handleChatInput(options: HandleChatInputOptions): Promise<ChatInputResult> {
  const content = options.line.trim();

  if (content.length === 0) {
    return "continue";
  }

  if (content === "/exit") {
    options.logger.info("CLI chat session ended", {
      sessionId: options.session.id
    });
    options.output.writeLine("Goodbye.");
    return "exit";
  }

  options.state.messages.push({
    role: "user",
    content
  });
  options.logger.info("CLI user message received", {
    sessionId: options.session.id,
    messageLength: content.length
  });

  const response = await options.provider.chat({
    messages: [...options.state.messages],
    metadata: {
      sessionId: options.session.id
    }
  });

  options.state.messages.push(response.message);
  options.output.writeLine(`Assistant: ${response.message.content}`);
  options.logger.info("CLI assistant response sent", {
    sessionId: options.session.id,
    messageLength: response.message.content.length
  });

  return "continue";
}

export async function runChatLoop(options: RunChatLoopOptions): Promise<void> {
  const state = createChatLoopState();
  const terminal = Boolean(options.input.isTTY && options.output.isTTY);
  const readline = createInterface({
    input: options.input,
    output: options.output,
    terminal,
    prompt: "> "
  });
  const chatOutput: ChatOutput = {
    writeLine(line) {
      options.output.write(`${line}\n`);
    }
  };

  options.output.write("Dominic Nexus local chat. Type /exit to quit.\n");
  options.logger.info("CLI chat session started", {
    sessionId: options.session.id
  });

  if (terminal) {
    readline.prompt();
  }

  try {
    for await (const line of readline) {
      const result = await handleChatInput({
        line,
        session: options.session,
        provider: options.provider,
        logger: options.logger,
        output: chatOutput,
        state
      });

      if (result === "exit") {
        break;
      }

      if (terminal) {
        readline.prompt();
      }
    }
  } finally {
    readline.close();
  }
}
