import { createInterface } from "node:readline";
import type { AgentSession } from "@dominic-nexus/core";
import type { Logger } from "@dominic-nexus/logging";
import type { ChatMessage } from "@dominic-nexus/providers";
import { ProviderRegistry } from "@dominic-nexus/providers";
import { providerName, serializeAppError, type ProviderName } from "@dominic-nexus/shared";

export interface ChatLoopState {
  messages: ChatMessage[];
}

export interface ChatOutput {
  writeLine(line: string): void;
}

export interface ChatQuestioner {
  question(query: string): Promise<string>;
  close(): void;
}

export type ChatInputResult = "continue" | "exit";

export interface HandleChatInputOptions {
  line: string;
  session: AgentSession;
  providers: ProviderRegistry;
  providerName?: ProviderName;
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
  providers: ProviderRegistry;
  providerName?: ProviderName;
  logger: Logger;
  questioner?: ChatQuestioner;
}

export function createChatLoopState(): ChatLoopState {
  return {
    messages: []
  };
}

export function createChatQuestioner(options: Pick<RunChatLoopOptions, "input" | "output">): ChatQuestioner {
  const terminal = Boolean(options.input.isTTY && options.output.isTTY);
  const readline = createInterface({
    input: options.input,
    output: options.output,
    terminal
  });
  const pendingLines: string[] = [];
  const waiters: Array<{
    resolve(line: string): void;
    reject(error: Error): void;
  }> = [];
  let closed = false;

  readline.on("line", (line) => {
    const waiter = waiters.shift();

    if (waiter === undefined) {
      pendingLines.push(line);
      return;
    }

    waiter.resolve(line);
  });

  readline.on("close", () => {
    closed = true;
    const error = new Error("CLI chat input closed");

    for (const waiter of waiters.splice(0)) {
      waiter.reject(error);
    }
  });

  return {
    question(query) {
      if (query.length > 0) {
        options.output.write(query);
      }

      const line = pendingLines.shift();
      if (line !== undefined) {
        return Promise.resolve(line);
      }

      if (closed) {
        return Promise.reject(new Error("CLI chat input closed"));
      }

      return new Promise((resolve, reject) => {
        waiters.push({ resolve, reject });
      });
    },
    close() {
      readline.close();
    }
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

  const userMessage: ChatMessage = {
    role: "user",
    content
  };
  options.logger.info("CLI user message received", {
    sessionId: options.session.id,
    messageLength: content.length
  });

  const selectedProviderName = options.providerName ?? providerName("mock");

  const response = await options.providers.chatResult(
    selectedProviderName,
    {
      messages: [...options.state.messages, userMessage],
      metadata: {
        sessionId: options.session.id
      }
    },
    {
      policy: options.session.runtime.policy,
      auditContext: {
        ...options.session.runtime,
        sessionId: options.session.id
      }
    }
  );

  if (!response.ok) {
    const serialized = serializeAppError(response.error);
    options.output.writeLine(`Error: ${serialized.message}`);
    options.logger.warn("CLI provider call failed", {
      sessionId: options.session.id,
      errorCode: serialized.code,
      errorMessage: serialized.message
    });
    return "continue";
  }

  options.state.messages.push(userMessage);
  options.state.messages.push(response.value.message);
  options.output.writeLine(`Assistant: ${response.value.message.content}`);
  options.logger.info("CLI assistant response sent", {
    sessionId: options.session.id,
    messageLength: response.value.message.content.length
  });

  return "continue";
}

export async function runChatLoop(options: RunChatLoopOptions): Promise<void> {
  const state = createChatLoopState();
  const terminal = Boolean(options.input.isTTY && options.output.isTTY);
  const questioner = options.questioner ?? createChatQuestioner(options);
  const chatOutput: ChatOutput = {
    writeLine(line) {
      options.output.write(`${line}\n`);
    }
  };

  options.output.write("Dominic Nexus local chat. Type /exit to quit.\n");
  options.logger.info("CLI chat session started", {
    sessionId: options.session.id
  });

  try {
    while (true) {
      let line: string;

      try {
        line = await questioner.question(terminal ? "> " : "");
      } catch {
        options.logger.info("CLI chat input closed", {
          sessionId: options.session.id
        });
        break;
      }

      const result = await handleChatInput({
        line,
        session: options.session,
        providers: options.providers,
        ...(options.providerName !== undefined ? { providerName: options.providerName } : {}),
        logger: options.logger,
        output: chatOutput,
        state
      });

      if (result === "exit") {
        break;
      }
    }
  } finally {
    questioner.close();
  }
}
