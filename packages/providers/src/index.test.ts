import { describe, expect, it } from "vitest";
import { InMemoryAuditSink } from "@dominic-nexus/audit";
import type { PermissionDecision, PermissionRequest, PolicyEngine } from "@dominic-nexus/permissions";
import { EnvSecretStore, envSecret, type SecretRef, type SecretStore } from "@dominic-nexus/secrets";
import { FixedClock, ok, providerName, REDACTED_PLACEHOLDER, SequentialIdGenerator, serializeAppError, type Result } from "@dominic-nexus/shared";
import {
  formatModelRef,
  MockProvider,
  OpenAIProvider,
  parseModelRef,
  ProviderRegistry,
  type ChatRequest,
  type ChatResponse,
  type ModelProvider,
  type ProviderModel,
  type ProviderTransport,
  type ProviderTransportRequest
} from "./index.js";

class RecordingPolicy implements PolicyEngine {
  readonly requests: PermissionRequest[] = [];

  constructor(private readonly decision: PermissionDecision = { allowed: true }) {}

  decide(request: PermissionRequest): PermissionDecision {
    this.requests.push(request);
    return this.decision;
  }
}

class ThrowingPolicy implements PolicyEngine {
  decide(): PermissionDecision {
    throw new Error("provider policy failed with secret-token");
  }
}

class ActionPolicy implements PolicyEngine {
  readonly requests: PermissionRequest[] = [];

  constructor(private readonly decisions: Partial<Record<PermissionRequest["action"], PermissionDecision>> = {}) {}

  decide(request: PermissionRequest): PermissionDecision {
    this.requests.push(request);
    return this.decisions[request.action] ?? { allowed: true };
  }
}

class RecordingSecretStore implements SecretStore {
  readonly refs: SecretRef[] = [];

  constructor(private readonly value: string | undefined) {}

  async read(ref: SecretRef): Promise<string | undefined> {
    this.refs.push(ref);
    return this.value;
  }
}

class ChatOnlyProvider implements ModelProvider {
  readonly name = providerName("chat-only");
  readonly capabilities = {
    chat: true,
    modelListing: false
  };

  async chat(): Promise<ChatResponse> {
    return {
      message: {
        role: "assistant",
        content: "chat-only"
      }
    };
  }
}

class RecordingChatProvider implements ModelProvider {
  readonly name = providerName("recording-chat");
  readonly capabilities = {
    chat: true,
    modelListing: false
  };
  readonly requests: ChatRequest[] = [];

  async chat(request: ChatRequest): Promise<ChatResponse> {
    this.requests.push(request);
    return {
      message: {
        role: "assistant",
        content: "recorded response"
      }
    };
  }
}

class ThrowingChatProvider implements ModelProvider {
  readonly name = providerName("throwing-chat");
  readonly capabilities = {
    chat: true,
    modelListing: false
  };

  async chat(): Promise<ChatResponse> {
    throw new Error("provider chat failed with secret-token");
  }
}

class ThrowingListModelsProvider implements ModelProvider {
  readonly name = providerName("throwing-list");
  readonly capabilities = {
    chat: true,
    modelListing: true
  };

  async chat(): Promise<ChatResponse> {
    return {
      message: {
        role: "assistant",
        content: "throwing-list"
      }
    };
  }

  async listModels(): Promise<never> {
    throw new Error("model listing failed with secret-token");
  }
}

class AbortDuringListModelsProvider implements ModelProvider {
  readonly name = providerName("abort-list");
  readonly capabilities = {
    chat: true,
    modelListing: true
  };

  constructor(private readonly controller: AbortController) {}

  async chat(): Promise<ChatResponse> {
    return {
      message: {
        role: "assistant",
        content: "abort-list"
      }
    };
  }

  async listModels(): Promise<Result<ProviderModel[]>> {
    this.controller.abort();
    return ok([
      {
        id: "model-after-abort"
      }
    ]);
  }
}

function createAuditContext() {
  const audit = new InMemoryAuditSink();

  return {
    audit,
    context: {
      audit,
      clock: new FixedClock("2026-05-08T00:00:00.000Z"),
      idGenerator: new SequentialIdGenerator({ eventPrefix: "provider-audit" })
    }
  };
}

function createRecordingTransport(response: {
  status: number;
  body: unknown;
} = {
  status: 200,
  body: {
    choices: [
      {
        message: {
          content: "openai response"
        }
      }
    ]
  }
}) {
  const requests: ProviderTransportRequest[] = [];
  const transport: ProviderTransport = async (request) => {
    requests.push(request);
    return response;
  };

  return {
    requests,
    transport
  };
}

describe("ModelRef", () => {
  it("parses simple provider/model refs", () => {
    const result = parseModelRef("openai/gpt-x");

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value).toEqual({
        provider: providerName("openai"),
        model: "gpt-x"
      });
    }

    const minimalResult = parseModelRef("a/b");
    expect(minimalResult.ok).toBe(true);
    if (minimalResult.ok) {
      expect(minimalResult.value).toEqual({
        provider: providerName("a"),
        model: "b"
      });
    }
  });

  it("splits on the first slash so model ids can contain slashes", () => {
    const result = parseModelRef("provider/vendor/model");

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value).toEqual({
        provider: providerName("provider"),
        model: "vendor/model"
      });
    }
  });

  it("preserves consecutive and trailing slash content in model ids", () => {
    const consecutiveSlashResult = parseModelRef("a//b");
    expect(consecutiveSlashResult.ok).toBe(true);
    if (consecutiveSlashResult.ok) {
      expect(consecutiveSlashResult.value).toEqual({
        provider: providerName("a"),
        model: "/b"
      });
    }

    const trailingSlashResult = parseModelRef("a/b/");
    expect(trailingSlashResult.ok).toBe(true);
    if (trailingSlashResult.ok) {
      expect(trailingSlashResult.value).toEqual({
        provider: providerName("a"),
        model: "b/"
      });
    }
  });

  it("normalizes surrounding whitespace deterministically", () => {
    const result = parseModelRef("  openai / gpt-x  ");

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(formatModelRef(result.value)).toBe("openai/gpt-x");
    }
  });

  it.each([
    ["missing slash", "openaigpt-x", "missing_separator"],
    ["empty provider", "/gpt-x", "empty_provider"],
    ["empty model", "openai/", "empty_model"],
    ["whitespace-only ref", "   ", "empty_ref"],
    ["whitespace-only provider", "   /gpt-x", "empty_provider"],
    ["whitespace-only model", "openai/   ", "empty_model"]
  ])("fails safely for invalid refs: %s", (_label, value, reason) => {
    const result = parseModelRef(value);

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(serializeAppError(result.error)).toEqual({
        name: "AppError",
        code: "provider.invalid_model_ref",
        message: "Invalid model ref",
        context: {
          reason
        }
      });
    }
  });

  it("formats parsed refs for round-trip use", () => {
    const result = parseModelRef("provider/vendor/model");

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(formatModelRef(result.value)).toBe("provider/vendor/model");
      expect(parseModelRef(formatModelRef(result.value))).toEqual(result);
    }
  });
});

describe("ProviderRegistry", () => {
  it("lists registered providers with capability snapshots", () => {
    const registry = new ProviderRegistry();
    const mock = new MockProvider(new RecordingPolicy());
    const chatOnly = new ChatOnlyProvider();

    registry.register(mock);
    registry.register(chatOnly);

    const providers = registry.listProviders();
    expect(providers).toEqual([
      {
        name: providerName("mock"),
        capabilities: {
          chat: true,
          modelListing: true
        }
      },
      {
        name: providerName("chat-only"),
        capabilities: {
          chat: true,
          modelListing: false
        }
      }
    ]);

    providers[0]!.capabilities.modelListing = false;
    expect(registry.listProviders()[0]?.capabilities.modelListing).toBe(true);
  });

  it("returns a safe AppError when a provider is missing", () => {
    const registry = new ProviderRegistry();

    const result = registry.getResult(providerName("missing"));

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(serializeAppError(result.error)).toEqual({
        name: "AppError",
        code: "provider.not_found",
        message: "Provider not found: missing",
        context: {
          providerName: "missing"
        }
      });
    }
  });

  it("lists models for providers that expose a catalog hook", async () => {
    const registry = new ProviderRegistry();
    registry.register(
      new MockProvider(new RecordingPolicy(), undefined, {
        models: [
          {
            id: "mock/default",
            label: "Default"
          },
          {
            id: "vendor/model/with/slashes"
          }
        ]
      })
    );

    const result = await registry.listModels(providerName("mock"));

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value).toEqual([
        {
          id: "mock/default",
          label: "Default"
        },
        {
          id: "vendor/model/with/slashes"
        }
      ]);
    }
  });

  it("isolates nested model metadata returned from listModels", async () => {
    const registry = new ProviderRegistry();
    registry.register(
      new MockProvider(new RecordingPolicy(), undefined, {
        models: [
          {
            id: "mock/default",
            metadata: {
              limits: {
                contexts: ["input"]
              },
              tags: ["stable"]
            }
          }
        ]
      })
    );

    const first = await registry.listModels(providerName("mock"));
    expect(first.ok).toBe(true);
    if (!first.ok) {
      return;
    }

    const firstMetadata = first.value[0]!.metadata!;
    (firstMetadata["limits"] as { contexts: string[] }).contexts.push("mutated");
    (firstMetadata["tags"] as string[]).push("mutated");

    const second = await registry.listModels(providerName("mock"));

    expect(second.ok).toBe(true);
    if (second.ok) {
      expect(second.value[0]?.metadata).toEqual({
        limits: {
          contexts: ["input"]
        },
        tags: ["stable"]
      });
    }
  });

  it("fails safely when model listing is unsupported", async () => {
    const registry = new ProviderRegistry();
    registry.register(new ChatOnlyProvider());

    const result = await registry.listModels(providerName("chat-only"));

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(serializeAppError(result.error)).toEqual({
        name: "AppError",
        code: "provider.model_listing_unsupported",
        message: "Provider does not support model listing: chat-only",
        context: {
          providerName: "chat-only"
        }
      });
    }
  });

  it("looks up supported models by exact model id", async () => {
    const registry = new ProviderRegistry();
    registry.register(
      new MockProvider(new RecordingPolicy(), undefined, {
        models: [
          {
            id: "vendor/model/with/slashes"
          }
        ]
      })
    );
    const ref = parseModelRef("mock/vendor/model/with/slashes");

    expect(ref.ok).toBe(true);
    if (!ref.ok) {
      return;
    }

    const result = await registry.getModel(ref.value);

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value).toEqual({
        id: "vendor/model/with/slashes"
      });
    }
  });

  it("isolates nested model metadata returned from getModel", async () => {
    const registry = new ProviderRegistry();
    registry.register(
      new MockProvider(new RecordingPolicy(), undefined, {
        models: [
          {
            id: "mock/default",
            metadata: {
              limits: {
                contexts: ["input"]
              },
              tags: ["stable"]
            }
          }
        ]
      })
    );
    const ref = parseModelRef("mock/mock/default");

    expect(ref.ok).toBe(true);
    if (!ref.ok) {
      return;
    }

    const first = await registry.getModel(ref.value);
    expect(first.ok).toBe(true);
    if (!first.ok) {
      return;
    }

    const firstMetadata = first.value.metadata!;
    (firstMetadata["limits"] as { contexts: string[] }).contexts.push("mutated");
    (firstMetadata["tags"] as string[]).push("mutated");

    const second = await registry.getModel(ref.value);

    expect(second.ok).toBe(true);
    if (second.ok) {
      expect(second.value.metadata).toEqual({
        limits: {
          contexts: ["input"]
        },
        tags: ["stable"]
      });
    }
  });

  it("fails safely when model lookup targets a missing provider", async () => {
    const registry = new ProviderRegistry();
    const ref = parseModelRef("missing/some-model");

    expect(ref.ok).toBe(true);
    if (!ref.ok) {
      return;
    }

    const result = await registry.getModel(ref.value);

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(serializeAppError(result.error)).toEqual({
        name: "AppError",
        code: "provider.not_found",
        message: "Provider not found: missing",
        context: {
          providerName: "missing"
        }
      });
    }
  });

  it("fails safely for unsupported model lookup", async () => {
    const registry = new ProviderRegistry();
    registry.register(new MockProvider(new RecordingPolicy()));
    const ref = parseModelRef("mock/missing-model");

    expect(ref.ok).toBe(true);
    if (!ref.ok) {
      return;
    }

    const result = await registry.getModel(ref.value);

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(serializeAppError(result.error)).toEqual({
        name: "AppError",
        code: "provider.unsupported_model",
        message: "Unsupported provider model: mock/missing-model",
        context: {
          providerName: "mock",
          model: "missing-model"
        }
      });
    }
  });

  it("fails safely when model lookup is cancelled before catalog lookup", async () => {
    const registry = new ProviderRegistry();
    registry.register(new MockProvider(new RecordingPolicy()));
    const ref = parseModelRef("mock/mock/default");
    const controller = new AbortController();
    controller.abort();

    expect(ref.ok).toBe(true);
    if (!ref.ok) {
      return;
    }

    const result = await registry.getModel(ref.value, { signal: controller.signal });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(serializeAppError(result.error)).toEqual({
        name: "AppError",
        code: "agent.turn_cancelled",
        message: "Model lookup cancelled: mock/mock/default",
        context: {
          providerName: "mock",
          model: "mock/default"
        }
      });
    }
  });

  it("fails safely when model lookup is cancelled after catalog lookup", async () => {
    const controller = new AbortController();
    const registry = new ProviderRegistry();
    registry.register(new AbortDuringListModelsProvider(controller));
    const ref = parseModelRef("abort-list/model-after-abort");

    expect(ref.ok).toBe(true);
    if (!ref.ok) {
      return;
    }

    const result = await registry.getModel(ref.value, { signal: controller.signal });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(serializeAppError(result.error)).toEqual({
        name: "AppError",
        code: "agent.turn_cancelled",
        message: "Model lookup cancelled: abort-list/model-after-abort",
        context: {
          providerName: "abort-list",
          model: "model-after-abort"
        }
      });
    }
  });

  it("normalizes thrown model listing failures without leaking thrown messages", async () => {
    const registry = new ProviderRegistry();
    registry.register(new ThrowingListModelsProvider());

    const result = await registry.listModels(providerName("throwing-list"));

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(serializeAppError(result.error)).toEqual({
        name: "AppError",
        code: "provider.execution_failed",
        message: "Provider model listing failed: throwing-list",
        context: {
          providerName: "throwing-list"
        }
      });
      expect(JSON.stringify(serializeAppError(result.error))).not.toContain("secret-token");
    }
  });

  it("executes chat through a centralized permission-gated registry path for plain providers", async () => {
    const { audit, context } = createAuditContext();
    const policy = new RecordingPolicy();
    const provider = new RecordingChatProvider();
    const registry = new ProviderRegistry();
    registry.register(provider);

    const result = await registry.chatResult(
      provider.name,
      {
        messages: [{ role: "user", content: "hello" }],
        model: "recording/default",
        metadata: {
          requestId: "request-1",
          apiKey: "secret-api-key"
        }
      },
      {
        policy,
        auditContext: context
      }
    );

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value).toEqual({
        message: {
          role: "assistant",
          content: "recorded response"
        }
      });
    }
    expect(provider.requests).toHaveLength(1);
    expect(policy.requests).toEqual([
      {
        action: "provider.call",
        reason: "Call recording-chat model provider",
        resource: "recording-chat",
        metadata: {
          requestId: "request-1",
          apiKey: "secret-api-key"
        }
      }
    ]);
    expect(audit.listEvents()).toEqual([
      expect.objectContaining({
        action: "permission.decide",
        decision: "allowed",
        outcome: "succeeded",
        metadata: expect.objectContaining({
          requestMetadata: {
            requestId: "request-1",
            apiKey: REDACTED_PLACEHOLDER
          }
        })
      }),
      expect.objectContaining({
        action: "provider.call",
        decision: "allowed",
        outcome: "succeeded",
        resource: expect.objectContaining({
          id: "recording-chat"
        }),
        metadata: {
          messageCount: 1,
          model: "recording/default"
        }
      })
    ]);
    expect(JSON.stringify(audit.listEvents())).not.toContain("secret-api-key");
  });

  it("does not call plain provider adapters when registry execution lacks a policy context", async () => {
    const provider = new RecordingChatProvider();
    const registry = new ProviderRegistry();
    registry.register(provider);

    const result = await registry.chatResult(provider.name, {
      messages: [{ role: "user", content: "hello" }]
    });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(serializeAppError(result.error)).toEqual({
        name: "AppError",
        code: "provider.execution_context_missing",
        message: "Provider execution context missing: recording-chat",
        context: {
          providerName: "recording-chat"
        }
      });
    }
    expect(provider.requests).toEqual([]);
  });

  it("does not call plain provider adapters when provider.call is denied and audits the denial", async () => {
    const { audit, context } = createAuditContext();
    const provider = new RecordingChatProvider();
    const registry = new ProviderRegistry();
    registry.register(provider);

    const result = await registry.chatResult(
      provider.name,
      {
        messages: [{ role: "user", content: "hello" }]
      },
      {
        policy: new RecordingPolicy({ allowed: false, reason: "provider denied centrally" }),
        auditContext: context
      }
    );

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(serializeAppError(result.error)).toEqual({
        name: "AppError",
        code: "provider.permission_denied",
        message: "Provider permission denied: recording-chat",
        context: {
          action: "provider.call",
          providerName: "recording-chat"
        }
      });
    }
    expect(provider.requests).toEqual([]);
    expect(audit.listEvents()).toEqual([
      expect.objectContaining({
        action: "permission.decide",
        decision: "denied",
        outcome: "denied"
      }),
      expect.objectContaining({
        action: "provider.call",
        decision: "denied",
        outcome: "denied",
        resource: expect.objectContaining({
          id: "recording-chat"
        }),
        metadata: {
          decisionReason: "provider denied centrally",
          messageCount: 1,
          model: null
        }
      })
    ]);
  });

  it("normalizes thrown centralized chat failures without leaking thrown messages", async () => {
    const { audit, context } = createAuditContext();
    const registry = new ProviderRegistry();
    registry.register(new ThrowingChatProvider());

    const result = await registry.chatResult(
      providerName("throwing-chat"),
      {
        messages: [{ role: "user", content: "hello" }]
      },
      {
        policy: new RecordingPolicy(),
        auditContext: context
      }
    );

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(serializeAppError(result.error)).toEqual({
        name: "AppError",
        code: "provider.execution_failed",
        message: "Provider execution failed: throwing-chat",
        context: {
          providerName: "throwing-chat"
        }
      });
      expect(JSON.stringify(serializeAppError(result.error))).not.toContain("secret-token");
    }
    expect(JSON.stringify(audit.listEvents())).not.toContain("secret-token");
  });

  it("executes existing permission-gated providers through the registry without duplicate permission checks", async () => {
    const { audit, context } = createAuditContext();
    const policy = new RecordingPolicy();
    const registry = new ProviderRegistry();
    const provider = new MockProvider(policy, context);
    registry.register(provider);

    const result = await registry.chatResult(
      providerName("mock"),
      {
        messages: [{ role: "user", content: "hello" }]
      },
      {
        policy,
        auditContext: context
      }
    );

    expect(result.ok).toBe(true);
    expect("chatUnchecked" in provider).toBe(false);
    expect(policy.requests).toHaveLength(1);
    expect(audit.listEvents()).toEqual([
      expect.objectContaining({
        action: "permission.decide",
        decision: "allowed"
      }),
      expect.objectContaining({
        action: "provider.call",
        decision: "allowed",
        outcome: "succeeded",
        resource: expect.objectContaining({
          id: "mock"
        })
      })
    ]);
  });
});

describe("OpenAIProvider", () => {
  it("denies direct chat calls through provider.call before resolving credentials or network", async () => {
    const { audit, context } = createAuditContext();
    const policy = new ActionPolicy({
      "provider.call": { allowed: false, reason: "provider disabled by policy" }
    });
    const secrets = new RecordingSecretStore("test-api-key");
    const transport = createRecordingTransport();
    const provider = new OpenAIProvider({
      apiKey: envSecret("OPENAI_API_KEY"),
      policy,
      secrets,
      auditContext: context,
      defaultModel: "gpt-test",
      transport: transport.transport
    });

    const result = await provider.chatResult({
      messages: [{ role: "user", content: "hello" }]
    });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(serializeAppError(result.error)).toEqual({
        name: "AppError",
        code: "provider.permission_denied",
        message: "Provider permission denied: openai",
        context: {
          action: "provider.call",
          providerName: "openai"
        }
      });
    }
    await expect(provider.chat({ messages: [{ role: "user", content: "hello" }] })).rejects.toMatchObject({
      code: "provider.permission_denied"
    });
    expect(secrets.refs).toEqual([]);
    expect(transport.requests).toEqual([]);
    expect(policy.requests.map((request) => request.action)).toEqual(["provider.call", "provider.call"]);
    expect(audit.listEvents()).toEqual([
      expect.objectContaining({
        action: "permission.decide",
        decision: "denied",
        outcome: "denied"
      }),
      expect.objectContaining({
        action: "provider.call",
        decision: "denied",
        outcome: "denied",
        resource: expect.objectContaining({
          id: "openai"
        })
      }),
      expect.objectContaining({
        action: "permission.decide",
        decision: "denied",
        outcome: "denied"
      }),
      expect.objectContaining({
        action: "provider.call",
        decision: "denied",
        outcome: "denied",
        resource: expect.objectContaining({
          id: "openai"
        })
      })
    ]);
  });

  it("is opt-in and still blocked by registry provider.call policy before resolving credentials", async () => {
    const { audit, context } = createAuditContext();
    const policy = new ActionPolicy({
      "provider.call": { allowed: false, reason: "provider disabled by policy" }
    });
    const secrets = new RecordingSecretStore("test-api-key");
    const transport = createRecordingTransport();
    const provider = new OpenAIProvider({
      apiKey: envSecret("OPENAI_API_KEY"),
      policy,
      secrets,
      auditContext: context,
      defaultModel: "gpt-test",
      transport: transport.transport
    });
    const registry = new ProviderRegistry();
    registry.register(provider);

    const result = await registry.chatResult(
      provider.name,
      {
        messages: [{ role: "user", content: "hello" }]
      },
      {
        policy,
        auditContext: context
      }
    );

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(serializeAppError(result.error)).toEqual({
        name: "AppError",
        code: "provider.permission_denied",
        message: "Provider permission denied: openai",
        context: {
          action: "provider.call",
          providerName: "openai"
        }
      });
    }
    expect(secrets.refs).toEqual([]);
    expect(transport.requests).toEqual([]);
    expect(policy.requests.map((request) => request.action)).toEqual(["provider.call"]);
    expect(audit.listEvents()).toEqual([
      expect.objectContaining({
        action: "permission.decide",
        decision: "denied",
        outcome: "denied"
      }),
      expect.objectContaining({
        action: "provider.call",
        decision: "denied",
        outcome: "denied",
        resource: expect.objectContaining({
          id: "openai"
        })
      })
    ]);
  });

  it("fails closed without calling transport when the API key is missing", async () => {
    const { context } = createAuditContext();
    const policy = new ActionPolicy();
    const secrets = new RecordingSecretStore(undefined);
    const transport = createRecordingTransport();
    const provider = new OpenAIProvider({
      apiKey: envSecret("OPENAI_API_KEY"),
      policy,
      secrets,
      auditContext: context,
      defaultModel: "gpt-test",
      transport: transport.transport
    });
    const registry = new ProviderRegistry();
    registry.register(provider);

    const result = await registry.chatResult(
      provider.name,
      {
        messages: [{ role: "user", content: "hello" }]
      },
      {
        policy,
        auditContext: context
      }
    );

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(serializeAppError(result.error)).toEqual({
        name: "AppError",
        code: "secret.unresolved",
        message: "Active secret could not be resolved",
        context: {
          name: "openai.apiKey",
          provider: "env",
          status: "unresolved"
        }
      });
    }
    expect(secrets.refs).toEqual([envSecret("OPENAI_API_KEY")]);
    expect(transport.requests).toEqual([]);
    expect(policy.requests.map((request) => request.action)).toEqual(["provider.call", "network.request"]);
  });

  it("fails closed without transport when secret.read is denied", async () => {
    const { audit, context } = createAuditContext();
    const policy = new ActionPolicy({
      "secret.read": { allowed: false, reason: "secret reads disabled" }
    });
    const secrets = new EnvSecretStore(policy, context, {
      OPENAI_API_KEY: "sk-secret-token"
    });
    const transport = createRecordingTransport();
    const provider = new OpenAIProvider({
      apiKey: envSecret("OPENAI_API_KEY"),
      policy,
      secrets,
      auditContext: context,
      defaultModel: "gpt-test",
      transport: transport.transport
    });
    const registry = new ProviderRegistry();
    registry.register(provider);

    const result = await registry.chatResult(
      provider.name,
      {
        messages: [{ role: "user", content: "hello" }]
      },
      {
        policy,
        auditContext: context
      }
    );

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(serializeAppError(result.error)).toEqual({
        name: "AppError",
        code: "secret.read_denied",
        message: "Secret read denied",
        context: {
          provider: "env",
          secretRef: REDACTED_PLACEHOLDER
        }
      });
    }
    expect(transport.requests).toEqual([]);
    expect(policy.requests.map((request) => request.action)).toEqual(["provider.call", "network.request", "secret.read"]);
    expect(JSON.stringify(audit.listEvents())).not.toContain("sk-secret-token");
  });

  it("fails closed without transport when network.request is denied", async () => {
    const { audit, context } = createAuditContext();
    const policy = new ActionPolicy({
      "network.request": { allowed: false, reason: "network disabled" }
    });
    const secrets = new RecordingSecretStore("sk-secret-token");
    const transport = createRecordingTransport();
    const provider = new OpenAIProvider({
      apiKey: envSecret("OPENAI_API_KEY"),
      policy,
      secrets,
      auditContext: context,
      defaultModel: "gpt-test",
      transport: transport.transport
    });
    const registry = new ProviderRegistry();
    registry.register(provider);

    const result = await registry.chatResult(
      provider.name,
      {
        messages: [{ role: "user", content: "hello" }]
      },
      {
        policy,
        auditContext: context
      }
    );

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(serializeAppError(result.error)).toEqual({
        name: "AppError",
        code: "permission.denied",
        message: "Network request permission denied",
        context: {
          action: "network.request",
          resource: "https://api.openai.com/v1/chat/completions"
        }
      });
    }
    expect(transport.requests).toEqual([]);
    expect(secrets.refs).toEqual([]);
    expect(policy.requests.map((request) => request.action)).toEqual(["provider.call", "network.request"]);
    expect(JSON.stringify(audit.listEvents())).not.toContain("sk-secret-token");
  });

  it("uses mocked transport after provider, secret, and network permissions allow the call", async () => {
    const { audit, context } = createAuditContext();
    const policy = new ActionPolicy();
    const secrets = new RecordingSecretStore("sk-secret-token");
    const transport = createRecordingTransport();
    const provider = new OpenAIProvider({
      apiKey: envSecret("OPENAI_API_KEY"),
      policy,
      secrets,
      auditContext: context,
      defaultModel: "gpt-test",
      transport: transport.transport
    });
    const registry = new ProviderRegistry();
    registry.register(provider);

    const result = await registry.chatResult(
      provider.name,
      {
        messages: [{ role: "user", content: "hello" }]
      },
      {
        policy,
        auditContext: context
      }
    );

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value).toEqual({
        message: {
          role: "assistant",
          content: "openai response"
        }
      });
    }
    expect(transport.requests).toHaveLength(1);
    const transportRequest = transport.requests[0]!;
    expect(transportRequest).toMatchObject({
      url: "https://api.openai.com/v1/chat/completions",
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: expect.stringMatching(/^Bearer .+$/u)
      },
      body: {
        model: "gpt-test",
        messages: [
          {
            role: "user",
            content: "hello"
          }
        ]
      }
    });
    expect(policy.requests.map((request) => request.action)).toEqual(["provider.call", "network.request"]);
    expect(audit.listEvents()).toEqual([
      expect.objectContaining({
        action: "permission.decide",
        decision: "allowed"
      }),
      expect.objectContaining({
        action: "permission.decide",
        decision: "allowed",
        resource: expect.objectContaining({
          id: "network.request"
        })
      }),
      expect.objectContaining({
        action: "provider.call",
        decision: "allowed",
        outcome: "succeeded",
        resource: expect.objectContaining({
          id: "openai"
        })
      })
    ]);
    expect(JSON.stringify(audit.listEvents())).not.toContain("sk-secret-token");
  });

  it("returns cancellation when a custom transport ignores an abort signal", async () => {
    const { audit, context } = createAuditContext();
    const policy = new ActionPolicy();
    const secrets = new RecordingSecretStore("sk-secret-token");
    const controller = new AbortController();
    const transportRequests: ProviderTransportRequest[] = [];
    const transport: ProviderTransport = async (request) => {
      transportRequests.push(request);
      controller.abort();
      return {
        status: 200,
        body: {
          choices: [
            {
              message: {
                content: "stale response"
              }
            }
          ]
        }
      };
    };
    const provider = new OpenAIProvider({
      apiKey: envSecret("OPENAI_API_KEY"),
      policy,
      secrets,
      auditContext: context,
      defaultModel: "gpt-test",
      transport
    });
    const registry = new ProviderRegistry();
    registry.register(provider);

    const result = await registry.chatResult(
      provider.name,
      {
        messages: [{ role: "user", content: "hello" }],
        signal: controller.signal
      },
      {
        policy,
        auditContext: context
      }
    );

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(serializeAppError(result.error)).toEqual({
        name: "AppError",
        code: "agent.turn_cancelled",
        message: "Provider call cancelled before completion: openai",
        context: {
          providerName: "openai"
        }
      });
    }
    expect(transportRequests).toHaveLength(1);
    expect(audit.listEvents()).toEqual([
      expect.objectContaining({
        action: "permission.decide",
        decision: "allowed"
      }),
      expect.objectContaining({
        action: "permission.decide",
        decision: "allowed",
        resource: expect.objectContaining({
          id: "network.request"
        })
      }),
      expect.objectContaining({
        action: "provider.call",
        decision: "allowed",
        outcome: "failed",
        metadata: expect.objectContaining({
          errorCode: "agent.turn_cancelled"
        })
      })
    ]);
  });

  it("normalizes failed transport responses without leaking credentials", async () => {
    const { audit, context } = createAuditContext();
    const policy = new ActionPolicy();
    const secrets = new RecordingSecretStore("sk-secret-token");
    const transport = createRecordingTransport({
      status: 401,
      body: {
        error: {
          message: "bad key sk-secret-token"
        }
      }
    });
    const provider = new OpenAIProvider({
      apiKey: envSecret("OPENAI_API_KEY"),
      policy,
      secrets,
      auditContext: context,
      defaultModel: "gpt-test",
      transport: transport.transport
    });
    const registry = new ProviderRegistry();
    registry.register(provider);

    const result = await registry.chatResult(
      provider.name,
      {
        messages: [{ role: "user", content: "hello" }]
      },
      {
        policy,
        auditContext: context
      }
    );

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(serializeAppError(result.error)).toEqual({
        name: "AppError",
        code: "provider.execution_failed",
        message: "OpenAI provider transport failed",
        context: {
          providerName: "openai",
          status: 401
        }
      });
      expect(JSON.stringify(serializeAppError(result.error))).not.toContain("sk-secret-token");
    }
    expect(transport.requests).toHaveLength(1);
    expect(JSON.stringify(audit.listEvents())).not.toContain("sk-secret-token");
  });
});

describe("MockProvider", () => {
  it("exposes provider capabilities and a default model catalog", async () => {
    const provider = new MockProvider(new RecordingPolicy());

    expect(provider.capabilities).toEqual({
      chat: true,
      modelListing: true
    });
    await expect(provider.listModels()).resolves.toEqual({
      ok: true,
      value: [
        {
          id: "mock/default",
          label: "Mock default model"
        }
      ]
    });
  });

  it("checks provider.call permission and echoes the last user message", async () => {
    const policy = new RecordingPolicy();
    const provider = new MockProvider(policy);

    const response = await provider.chat({
      messages: [
        { role: "system", content: "You are local." },
        { role: "user", content: "first" },
        { role: "assistant", content: "reply" },
        { role: "user", content: "second" }
      ],
      metadata: { requestId: "request-1" }
    });

    expect(response).toEqual({
      message: {
        role: "assistant",
        content: "second"
      }
    });
    expect(policy.requests).toEqual([
      {
        action: "provider.call",
        reason: "Call mock model provider",
        resource: "mock",
        metadata: { requestId: "request-1" }
      }
    ]);
  });

  it("audits allowed provider calls and redacts request metadata", async () => {
    const { audit, context } = createAuditContext();
    const provider = new MockProvider(new RecordingPolicy(), context);

    await provider.chat({
      messages: [{ role: "user", content: "hello" }],
      model: "mock/default",
      metadata: {
        requestId: "request-1",
        apiKey: "secret-api-key"
      }
    });

    const events = audit.listEvents();
    expect(events).toHaveLength(2);
    expect(events[0]).toMatchObject({
      action: "permission.decide",
      decision: "allowed",
      outcome: "succeeded",
      metadata: {
        requestMetadata: {
          requestId: "request-1",
          apiKey: REDACTED_PLACEHOLDER
        }
      }
    });
    expect(events[1]).toMatchObject({
      action: "provider.call",
      decision: "allowed",
      outcome: "succeeded",
      resource: {
        type: "provider",
        id: "mock"
      },
      metadata: {
        messageCount: 1,
        model: "mock/default"
      }
    });
    expect(JSON.stringify(events)).not.toContain("secret-api-key");
  });

  it("audits provider policy failures without leaking thrown messages", async () => {
    const { audit, context } = createAuditContext();
    const provider = new MockProvider(new ThrowingPolicy(), context);

    const result = await provider.chatResult({
      messages: [{ role: "user", content: "hello" }],
      model: "mock/default"
    });

    expect(result.ok).toBe(false);

    const events = audit.listEvents();
    expect(events).toEqual([
      expect.objectContaining({
        action: "provider.call",
        decision: "not_applicable",
        outcome: "failed",
        resource: expect.objectContaining({
          id: "mock"
        }),
        metadata: expect.objectContaining({
          errorName: "Error"
        })
      })
    ]);
    expect(JSON.stringify(events)).not.toContain("provider policy failed with secret-token");
    expect(JSON.stringify(events)).not.toContain("secret-token");
  });

  it("returns the default mock response for empty messages and audits success", async () => {
    const { audit, context } = createAuditContext();
    const provider = new MockProvider(new RecordingPolicy(), context);

    const response = await provider.chat({
      messages: []
    });

    expect(response).toEqual({
      message: {
        role: "assistant",
        content: "Mock provider response."
      }
    });
    expect(audit.listEvents()).toEqual([
      expect.objectContaining({
        action: "permission.decide",
        decision: "allowed",
        outcome: "succeeded"
      }),
      expect.objectContaining({
        action: "provider.call",
        decision: "allowed",
        outcome: "succeeded",
        resource: expect.objectContaining({
          id: "mock"
        }),
        metadata: {
          messageCount: 0,
          model: null
        }
      })
    ]);
  });

  it("returns a safe AppError when provider.call permission is denied", async () => {
    const provider = new MockProvider(new RecordingPolicy({ allowed: false, reason: "provider denied" }));

    const result = await provider.chatResult({ messages: [{ role: "user", content: "hello" }] });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(serializeAppError(result.error)).toEqual({
        name: "AppError",
        code: "provider.permission_denied",
        message: "Provider permission denied: mock",
        context: {
          action: "provider.call",
          providerName: "mock"
        }
      });
    }
    await expect(provider.chat({ messages: [{ role: "user", content: "hello" }] })).rejects.toMatchObject({
      code: "provider.permission_denied"
    });
  });

  it("returns a safe AppError and audits without permission checks when called with an already aborted signal", async () => {
    const { audit, context } = createAuditContext();
    const policy = new RecordingPolicy();
    const provider = new MockProvider(policy, context);
    const controller = new AbortController();
    controller.abort();

    const result = await provider.chatResult({
      messages: [{ role: "user", content: "hello" }],
      signal: controller.signal
    });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(serializeAppError(result.error)).toEqual({
        name: "AppError",
        code: "agent.turn_cancelled",
        message: "Provider call cancelled before execution: mock",
        context: {
          providerName: "mock"
        }
      });
    }
    expect(policy.requests).toEqual([]);
    expect(audit.listEvents()).toEqual([
      expect.objectContaining({
        sourcePackage: "@dominic-nexus/providers",
        action: "provider.call",
        decision: "not_applicable",
        outcome: "failed",
        resource: expect.objectContaining({
          id: "mock"
        }),
        metadata: {
          errorCode: "agent.turn_cancelled",
          errorMessage: "Provider call cancelled before execution: mock",
          messageCount: 1,
          model: null
        }
      })
    ]);
  });

  it("audits denied provider permission decisions", async () => {
    const { audit, context } = createAuditContext();
    const provider = new MockProvider(new RecordingPolicy({ allowed: false, reason: "provider denied" }), context);

    const result = await provider.chatResult({ messages: [{ role: "user", content: "hello" }] });

    expect(result.ok).toBe(false);
    expect(audit.listEvents()).toEqual([
      expect.objectContaining({
        action: "permission.decide",
        decision: "denied",
        outcome: "denied",
        resource: expect.objectContaining({
          id: "provider.call"
        })
      }),
      expect.objectContaining({
        action: "provider.call",
        decision: "denied",
        outcome: "denied",
        resource: expect.objectContaining({
          id: "mock"
        })
      })
    ]);
  });
});
