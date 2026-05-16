import { appendAuditEvent, type OptionalAuditRuntimeContext } from "@dominic-nexus/audit";
import {
  decidePermissionWithAudit,
  NetworkPolicy,
  type PermissionDecision,
  type PermissionRequest,
  type PolicyEngine
} from "@dominic-nexus/permissions";
import { resolveSecretRef, type SecretRef, type SecretStore } from "@dominic-nexus/secrets";
import {
  AppError,
  err,
  isJsonObject,
  ok,
  providerName,
  toAppError,
  type JsonObject,
  type JsonValue,
  type ProviderName,
  type Result
} from "@dominic-nexus/shared";

export type ChatRole = "system" | "user" | "assistant" | "tool";

export type ModelRefInvalidReason = "empty_ref" | "missing_separator" | "empty_provider" | "empty_model";

export interface ModelRef {
  provider: ProviderName;
  model: string;
}

function invalidModelRef(reason: ModelRefInvalidReason): Result<never> {
  return err(
    new AppError({
      code: "provider.invalid_model_ref",
      message: "Invalid model ref",
      context: {
        reason
      }
    })
  );
}

export function parseModelRef(value: string): Result<ModelRef> {
  const normalized = value.trim();
  if (normalized.length === 0) {
    return invalidModelRef("empty_ref");
  }

  const separatorIndex = normalized.indexOf("/");
  if (separatorIndex < 0) {
    return invalidModelRef("missing_separator");
  }

  const provider = normalized.slice(0, separatorIndex).trim();
  if (provider.length === 0) {
    return invalidModelRef("empty_provider");
  }

  const model = normalized.slice(separatorIndex + 1).trim();
  if (model.length === 0) {
    return invalidModelRef("empty_model");
  }

  return ok({
    provider: providerName(provider),
    model
  });
}

export function formatModelRef(ref: ModelRef): string {
  return `${ref.provider}/${ref.model}`;
}

export interface ChatMessage {
  role: ChatRole;
  content: string;
  metadata?: Record<string, JsonValue>;
}

export interface ChatRequest {
  messages: ChatMessage[];
  model?: string;
  metadata?: Record<string, JsonValue>;
  signal?: AbortSignal;
}

export interface ChatResponse {
  message: ChatMessage;
  metadata?: Record<string, JsonValue>;
}

export interface ProviderExecutionContext {
  policy: PolicyEngine;
  auditContext?: OptionalAuditRuntimeContext;
}

export interface ProviderCapabilities {
  chat: boolean;
  modelListing: boolean;
}

export interface ProviderModel {
  id: string;
  label?: string;
  metadata?: Record<string, JsonValue>;
}

export interface ListModelsRequest {
  metadata?: Record<string, JsonValue>;
  signal?: AbortSignal;
}

export interface ModelProvider {
  name: ProviderName;
  capabilities: ProviderCapabilities;
  chat(request: ChatRequest): Promise<ChatResponse>;
  listModels?(request?: ListModelsRequest): Promise<Result<ProviderModel[]>>;
}

export interface ProviderTransportRequest {
  url: string;
  method: "POST";
  headers: Record<string, string>;
  body: JsonObject;
  signal?: AbortSignal;
}

export interface ProviderTransportResponse {
  status: number;
  body: unknown;
}

export type ProviderTransport = (request: ProviderTransportRequest) => Promise<ProviderTransportResponse>;

export interface PermissionGatedChatProvider extends ModelProvider {
  chatResult(request: ChatRequest): Promise<Result<ChatResponse>>;
}

const providerRawChat = Symbol("provider.raw_chat");

interface ProviderRawChatAdapter extends ModelProvider {
  [providerRawChat](request: ChatRequest): Promise<ChatResponse>;
}

export interface ProviderDescriptor {
  name: ProviderName;
  capabilities: ProviderCapabilities;
}

export interface OpenAIProviderOptions {
  apiKey: SecretRef;
  policy: PolicyEngine;
  secrets: SecretStore;
  auditContext?: OptionalAuditRuntimeContext;
  defaultModel?: string;
  endpoint?: string;
  organization?: string;
  transport?: ProviderTransport;
}

function cloneCapabilities(capabilities: ProviderCapabilities): ProviderCapabilities {
  return {
    chat: capabilities.chat,
    modelListing: capabilities.modelListing
  };
}

function cloneJsonValue(value: JsonValue): JsonValue {
  if (Array.isArray(value)) {
    return value.map((item) => cloneJsonValue(item));
  }

  if (value !== null && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, cloneJsonValue(item)]));
  }

  return value;
}

function cloneJsonRecord(record: Record<string, JsonValue>): Record<string, JsonValue> {
  return Object.fromEntries(Object.entries(record).map(([key, value]) => [key, cloneJsonValue(value)]));
}

function cloneModel(model: ProviderModel): ProviderModel {
  return {
    id: model.id,
    ...(model.label !== undefined ? { label: model.label } : {}),
    ...(model.metadata !== undefined ? { metadata: cloneJsonRecord(model.metadata) } : {})
  };
}

function providerNotFound(name: ProviderName): Result<never> {
  return err(
    new AppError({
      code: "provider.not_found",
      message: `Provider not found: ${name}`,
      context: {
        providerName: name
      }
    })
  );
}

function modelListingUnsupported(name: ProviderName): Result<never> {
  return err(
    new AppError({
      code: "provider.model_listing_unsupported",
      message: `Provider does not support model listing: ${name}`,
      context: {
        providerName: name
      }
    })
  );
}

function unsupportedModel(ref: ModelRef): Result<never> {
  return err(
    new AppError({
      code: "provider.unsupported_model",
      message: `Unsupported provider model: ${formatModelRef(ref)}`,
      context: {
        providerName: ref.provider,
        model: ref.model
      }
    })
  );
}

function modelLookupCancelled(ref: ModelRef): Result<never> {
  return err(
    new AppError({
      code: "agent.turn_cancelled",
      message: `Model lookup cancelled: ${formatModelRef(ref)}`,
      context: {
        providerName: ref.provider,
        model: ref.model
      }
    })
  );
}

function providerExecutionContextMissing(name: ProviderName): Result<never> {
  return err(
    new AppError({
      code: "provider.execution_context_missing",
      message: `Provider execution context missing: ${name}`,
      context: {
        providerName: name
      }
    })
  );
}

function providerChatUnsupported(name: ProviderName): Result<never> {
  return err(
    new AppError({
      code: "provider.chat_unsupported",
      message: `Provider does not support chat: ${name}`,
      context: {
        providerName: name
      }
    })
  );
}

function providerExecutionFailed(name: ProviderName, message: string, context: Record<string, JsonValue> = {}): AppError {
  return new AppError({
    code: "provider.execution_failed",
    message,
    context: {
      providerName: name,
      ...context
    }
  });
}

function normalizeOpenAIEndpoint(value: string | undefined): Result<string> {
  const endpoint = value ?? "https://api.openai.com/v1/chat/completions";

  let parsed: URL;
  try {
    parsed = new URL(endpoint);
  } catch {
    return err(
      providerExecutionFailed(providerName("openai"), "OpenAI provider endpoint is invalid", {
        reason: "invalid_endpoint"
      })
    );
  }

  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
    return err(
      providerExecutionFailed(providerName("openai"), "OpenAI provider endpoint protocol is unsupported", {
        reason: "unsupported_endpoint_protocol",
        protocol: parsed.protocol
      })
    );
  }

  return ok(parsed.href);
}

async function defaultProviderTransport(request: ProviderTransportRequest): Promise<ProviderTransportResponse> {
  if (typeof globalThis.fetch !== "function") {
    throw new AppError({
      code: "provider.execution_failed",
      message: "Provider transport is unavailable",
      context: {
        reason: "fetch_unavailable"
      }
    });
  }

  const init: RequestInit = {
    method: request.method,
    headers: request.headers,
    body: JSON.stringify(request.body)
  };

  if (request.signal !== undefined) {
    init.signal = request.signal;
  }

  const response = await globalThis.fetch(request.url, init);
  let body: unknown = null;

  try {
    body = await response.json();
  } catch {
    body = null;
  }

  return {
    status: response.status,
    body
  };
}

function extractOpenAIContent(body: unknown, provider: ProviderName): Result<string> {
  if (!isJsonObject(body)) {
    return err(
      providerExecutionFailed(provider, "OpenAI provider returned an invalid response", {
        reason: "invalid_response_body"
      })
    );
  }

  const choices = body.choices;
  if (!Array.isArray(choices) || choices.length === 0) {
    return err(
      providerExecutionFailed(provider, "OpenAI provider returned no choices", {
        reason: "missing_choices"
      })
    );
  }

  const [firstChoice] = choices;
  if (!isJsonObject(firstChoice) || !isJsonObject(firstChoice.message) || typeof firstChoice.message.content !== "string") {
    return err(
      providerExecutionFailed(provider, "OpenAI provider returned an invalid message", {
        reason: "invalid_choice_message"
      })
    );
  }

  return ok(firstChoice.message.content);
}

function isSignalAborted(signal: AbortSignal | undefined): boolean {
  return signal?.aborted === true;
}

function isRawChatAdapter(provider: ModelProvider): provider is ProviderRawChatAdapter {
  return (
    providerRawChat in provider &&
    typeof (provider as Partial<Record<typeof providerRawChat, unknown>>)[providerRawChat] === "function"
  );
}

async function auditProviderCall(
  auditContext: OptionalAuditRuntimeContext | undefined,
  options: {
    decision: "allowed" | "denied" | "not_applicable";
    messageCount: number;
    model?: string | undefined;
    outcome: "succeeded" | "failed" | "denied";
    providerName: ProviderName;
    error?: AppError;
    decisionReason?: string | undefined;
  }
): Promise<void> {
  const sessionId = auditContext?.sessionId;

  await appendAuditEvent(auditContext, {
    sourcePackage: "@dominic-nexus/providers",
    action: "provider.call",
    decision: options.decision,
    ...(sessionId !== undefined ? { sessionId } : {}),
    resource: {
      type: "provider",
      id: options.providerName,
      name: options.providerName
    },
    outcome: options.outcome,
    metadata: {
      messageCount: options.messageCount,
      model: options.model ?? null,
      ...(options.decisionReason !== undefined ? { decisionReason: options.decisionReason } : {}),
      ...(options.error !== undefined
        ? {
            errorCode: options.error.code,
            errorMessage: options.error.message
          }
        : {})
    }
  });
}

export class ProviderRegistry {
  private readonly providers = new Map<ProviderName, ModelProvider>();

  register(provider: ModelProvider): void {
    this.providers.set(provider.name, provider);
  }

  get(name: ProviderName): ModelProvider | undefined {
    return this.providers.get(name);
  }

  getResult(name: ProviderName): Result<ModelProvider> {
    const provider = this.get(name);
    if (provider === undefined) {
      return providerNotFound(name);
    }

    return ok(provider);
  }

  listProviders(): ProviderDescriptor[] {
    return [...this.providers.values()].map((provider) => ({
      name: provider.name,
      capabilities: cloneCapabilities(provider.capabilities)
    }));
  }

  async listModels(name: ProviderName, request: ListModelsRequest = {}): Promise<Result<ProviderModel[]>> {
    const providerResult = this.getResult(name);
    if (!providerResult.ok) {
      return providerResult;
    }

    const provider = providerResult.value;
    if (!provider.capabilities.modelListing || provider.listModels === undefined) {
      return modelListingUnsupported(name);
    }

    try {
      const result = await provider.listModels(request);
      if (!result.ok) {
        return result;
      }

      return ok(result.value.map((model) => cloneModel(model)));
    } catch (error) {
      return err(
        toAppError(error, {
          code: "provider.execution_failed",
          message: `Provider model listing failed: ${name}`,
          context: {
            providerName: name
          }
        })
      );
    }
  }

  async getModel(ref: ModelRef, request: ListModelsRequest = {}): Promise<Result<ProviderModel>> {
    if (isSignalAborted(request.signal)) {
      return modelLookupCancelled(ref);
    }

    const modelsResult = await this.listModels(ref.provider, request);
    if (!modelsResult.ok) {
      return modelsResult;
    }

    if (isSignalAborted(request.signal)) {
      return modelLookupCancelled(ref);
    }

    const model = modelsResult.value.find((item) => item.id === ref.model);
    if (model === undefined) {
      return unsupportedModel(ref);
    }

    return ok(cloneModel(model));
  }

  async chatResult(
    name: ProviderName,
    request: ChatRequest,
    executionContext?: ProviderExecutionContext
  ): Promise<Result<ChatResponse>> {
    const providerResult = this.getResult(name);
    if (!providerResult.ok) {
      return providerResult;
    }

    const provider = providerResult.value;
    if (!provider.capabilities.chat) {
      return providerChatUnsupported(name);
    }

    if (executionContext === undefined) {
      return providerExecutionContextMissing(name);
    }

    const permissionRequest: PermissionRequest = {
      action: "provider.call",
      reason: `Call ${name} model provider`,
      resource: name
    };

    if (request.metadata !== undefined) {
      permissionRequest.metadata = request.metadata;
    }

    let decision: PermissionDecision;

    try {
      decision = await decidePermissionWithAudit(executionContext.policy, permissionRequest, executionContext.auditContext);
    } catch (error) {
      const appError = toAppError(error, {
        code: "provider.execution_failed",
        message: `Provider execution failed: ${name}`,
        context: {
          providerName: name
        }
      });
      await auditProviderCall(executionContext.auditContext, {
        decision: "not_applicable",
        error: appError,
        messageCount: request.messages.length,
        model: request.model,
        outcome: "failed",
        providerName: name
      });
      return err(appError);
    }

    if (!decision.allowed) {
      await auditProviderCall(executionContext.auditContext, {
        decision: "denied",
        decisionReason: decision.reason,
        messageCount: request.messages.length,
        model: request.model,
        outcome: "denied",
        providerName: name
      });
      return err(
        new AppError({
          code: "provider.permission_denied",
          message: `Provider permission denied: ${name}`,
          context: {
            action: "provider.call",
            providerName: name
          }
        })
      );
    }

    try {
      const response = await (isRawChatAdapter(provider) ? provider[providerRawChat](request) : provider.chat(request));
      if (isSignalAborted(request.signal)) {
        const appError = new AppError({
          code: "agent.turn_cancelled",
          message: `Provider call cancelled before completion: ${name}`,
          context: {
            providerName: name
          }
        });
        await auditProviderCall(executionContext.auditContext, {
          decision: "allowed",
          error: appError,
          messageCount: request.messages.length,
          model: request.model,
          outcome: "failed",
          providerName: name
        });
        return err(
          appError
        );
      }

      await auditProviderCall(executionContext.auditContext, {
        decision: "allowed",
        messageCount: request.messages.length,
        model: request.model,
        outcome: "succeeded",
        providerName: name
      });
      return ok(response);
    } catch (error) {
      if (isSignalAborted(request.signal)) {
        const appError = new AppError({
          code: "agent.turn_cancelled",
          message: `Provider call cancelled before completion: ${name}`,
          context: {
            providerName: name
          }
        });
        await auditProviderCall(executionContext.auditContext, {
          decision: "allowed",
          error: appError,
          messageCount: request.messages.length,
          model: request.model,
          outcome: "failed",
          providerName: name
        });
        return err(
          appError
        );
      }

      const appError = toAppError(error, {
        code: "provider.execution_failed",
        message: `Provider execution failed: ${name}`,
        context: {
          providerName: name
        }
      });
      await auditProviderCall(executionContext.auditContext, {
        decision: "allowed",
        error: appError,
        messageCount: request.messages.length,
        model: request.model,
        outcome: "failed",
        providerName: name
      });
      return err(appError);
    }
  }
}

export class OpenAIProvider implements ModelProvider {
  readonly name = providerName("openai");
  readonly capabilities: ProviderCapabilities = {
    chat: true,
    modelListing: false
  };

  private readonly apiKey: SecretRef;
  private readonly auditContext: OptionalAuditRuntimeContext | undefined;
  private readonly defaultModel: string | undefined;
  private readonly endpoint: string;
  private readonly networkPolicy: NetworkPolicy;
  private readonly organization: string | undefined;
  private readonly policy: PolicyEngine;
  private readonly secrets: SecretStore;
  private readonly transport: ProviderTransport;

  constructor(options: OpenAIProviderOptions) {
    const endpoint = normalizeOpenAIEndpoint(options.endpoint);
    if (!endpoint.ok) {
      throw endpoint.error;
    }

    this.apiKey = options.apiKey;
    this.auditContext = options.auditContext;
    this.defaultModel = options.defaultModel;
    this.endpoint = endpoint.value;
    this.networkPolicy = new NetworkPolicy(options.policy);
    this.organization = options.organization;
    this.policy = options.policy;
    this.secrets = options.secrets;
    this.transport = options.transport ?? defaultProviderTransport;
  }

  async chat(request: ChatRequest): Promise<ChatResponse> {
    const result = await this.chatResult(request);

    if (!result.ok) {
      throw result.error;
    }

    return result.value;
  }

  async chatResult(request: ChatRequest): Promise<Result<ChatResponse>> {
    if (isSignalAborted(request.signal)) {
      const error = new AppError({
        code: "agent.turn_cancelled",
        message: `Provider call cancelled before execution: ${this.name}`,
        context: {
          providerName: this.name
        }
      });
      await auditProviderCall(this.auditContext, {
        decision: "not_applicable",
        error,
        messageCount: request.messages.length,
        model: request.model,
        outcome: "failed",
        providerName: this.name
      });

      return err(error);
    }

    const permissionRequest: PermissionRequest = {
      action: "provider.call",
      reason: "Call openai model provider",
      resource: this.name
    };

    if (request.metadata !== undefined) {
      permissionRequest.metadata = request.metadata;
    }

    let decision: PermissionDecision;

    try {
      decision = await decidePermissionWithAudit(this.policy, permissionRequest, this.auditContext);
    } catch (error) {
      const appError = toAppError(error, {
        code: "provider.execution_failed",
        message: `Provider execution failed: ${this.name}`,
        context: {
          providerName: this.name
        }
      });
      await auditProviderCall(this.auditContext, {
        decision: "not_applicable",
        error: appError,
        messageCount: request.messages.length,
        model: request.model,
        outcome: "failed",
        providerName: this.name
      });
      return err(appError);
    }

    if (!decision.allowed) {
      await auditProviderCall(this.auditContext, {
        decision: "denied",
        decisionReason: decision.reason,
        messageCount: request.messages.length,
        model: request.model,
        outcome: "denied",
        providerName: this.name
      });
      return err(
        new AppError({
          code: "provider.permission_denied",
          message: `Provider permission denied: ${this.name}`,
          context: {
            action: "provider.call",
            providerName: this.name
          }
        })
      );
    }

    try {
      const response = await this[providerRawChat](request);
      if (isSignalAborted(request.signal)) {
        const error = new AppError({
          code: "agent.turn_cancelled",
          message: `Provider call cancelled before completion: ${this.name}`,
          context: {
            providerName: this.name
          }
        });
        await auditProviderCall(this.auditContext, {
          decision: "allowed",
          error,
          messageCount: request.messages.length,
          model: request.model,
          outcome: "failed",
          providerName: this.name
        });
        return err(error);
      }

      await auditProviderCall(this.auditContext, {
        decision: "allowed",
        messageCount: request.messages.length,
        model: request.model,
        outcome: "succeeded",
        providerName: this.name
      });
      return ok(response);
    } catch (error) {
      if (isSignalAborted(request.signal)) {
        const appError = new AppError({
          code: "agent.turn_cancelled",
          message: `Provider call cancelled before completion: ${this.name}`,
          context: {
            providerName: this.name
          }
        });
        await auditProviderCall(this.auditContext, {
          decision: "allowed",
          error: appError,
          messageCount: request.messages.length,
          model: request.model,
          outcome: "failed",
          providerName: this.name
        });
        return err(appError);
      }

      const appError = toAppError(error, {
        code: "provider.execution_failed",
        message: `Provider execution failed: ${this.name}`,
        context: {
          providerName: this.name
        }
      });
      await auditProviderCall(this.auditContext, {
        decision: "allowed",
        error: appError,
        messageCount: request.messages.length,
        model: request.model,
        outcome: "failed",
        providerName: this.name
      });
      return err(appError);
    }
  }

  async [providerRawChat](request: ChatRequest): Promise<ChatResponse> {
    const model = request.model ?? this.defaultModel;
    if (model === undefined || model.trim().length === 0) {
      throw providerExecutionFailed(this.name, "OpenAI provider requires a model", {
        reason: "missing_model"
      });
    }

    const networkAuthorizeOptions = {
      reason: "Call OpenAI chat completions endpoint",
      metadata: {
        providerName: this.name,
        model
      },
      ...(this.auditContext !== undefined ? { audit: this.auditContext } : {})
    };
    const networkApproval = await this.networkPolicy.authorize(
      {
        url: this.endpoint,
        method: "POST"
      },
      networkAuthorizeOptions
    );
    if (!networkApproval.ok) {
      throw networkApproval.error;
    }

    const credential = await resolveSecretRef(this.apiKey, {
      name: "openai.apiKey",
      store: this.secrets
    });
    if (!credential.ok) {
      throw credential.error;
    }

    if (credential.value.status !== "resolved") {
      throw new AppError({
        code: "secret.unresolved",
        message: "Active secret could not be resolved",
        context: {
          name: "openai.apiKey",
          provider: credential.value.warning.provider,
          status: credential.value.warning.status
        }
      });
    }

    const headers: Record<string, string> = {
      "content-type": "application/json",
      authorization: `Bearer ${credential.value.secret.reveal()}`
    };
    if (this.organization !== undefined) {
      headers["openai-organization"] = this.organization;
    }

    const body: JsonObject = {
      model,
      messages: request.messages.map((message) => ({
        role: message.role,
        content: message.content
      }))
    };

    const transportRequest: ProviderTransportRequest = {
      url: this.endpoint,
      method: "POST",
      headers,
      body
    };
    if (request.signal !== undefined) {
      transportRequest.signal = request.signal;
    }

    const response = await this.transport(transportRequest);
    if (response.status < 200 || response.status >= 300) {
      throw providerExecutionFailed(this.name, "OpenAI provider transport failed", {
        status: response.status
      });
    }

    const content = extractOpenAIContent(response.body, this.name);
    if (!content.ok) {
      throw content.error;
    }

    return {
      message: {
        role: "assistant",
        content: content.value
      }
    };
  }
}

export interface MockProviderOptions {
  models?: ProviderModel[];
}

export class MockProvider implements ModelProvider {
  readonly name = providerName("mock");
  readonly capabilities: ProviderCapabilities = {
    chat: true,
    modelListing: true
  };

  private readonly models: ProviderModel[];

  constructor(
    private readonly policy: PolicyEngine,
    private readonly auditContext?: OptionalAuditRuntimeContext,
    options: MockProviderOptions = {}
  ) {
    this.models = (
      options.models ?? [
        {
          id: "mock/default",
          label: "Mock default model"
        }
      ]
    ).map((model) => cloneModel(model));
  }

  /**
   * Standalone compatibility path for direct provider tests.
   * Runtime callers should use ProviderRegistry.chatResult() so provider.call
   * permission and audit are applied centrally.
   */
  async chat(request: ChatRequest): Promise<ChatResponse> {
    const result = await this.chatResult(request);

    if (!result.ok) {
      throw result.error;
    }

    return result.value;
  }

  async chatResult(request: ChatRequest): Promise<Result<ChatResponse>> {
    if (request.signal?.aborted === true) {
      const error = new AppError({
        code: "agent.turn_cancelled",
        message: `Provider call cancelled before execution: ${this.name}`,
        context: {
          providerName: this.name
        }
      });
      await appendAuditEvent(this.auditContext, {
        sourcePackage: "@dominic-nexus/providers",
        action: "provider.call",
        decision: "not_applicable",
        resource: {
          type: "provider",
          id: this.name,
          name: this.name
        },
        outcome: "failed",
        metadata: {
          errorCode: error.code,
          errorMessage: error.message,
          messageCount: request.messages.length,
          model: request.model ?? null
        }
      });

      return err(error);
    }

    const permissionRequest: PermissionRequest = {
      action: "provider.call",
      reason: "Call mock model provider",
      resource: this.name
    };

    if (request.metadata !== undefined) {
      permissionRequest.metadata = request.metadata;
    }

    let decision: PermissionDecision;

    try {
      decision = await decidePermissionWithAudit(this.policy, permissionRequest, this.auditContext);
    } catch (error) {
      await appendAuditEvent(this.auditContext, {
        sourcePackage: "@dominic-nexus/providers",
        action: "provider.call",
        decision: "not_applicable",
        resource: {
          type: "provider",
          id: this.name,
          name: this.name
        },
        outcome: "failed",
        metadata: {
          errorName: error instanceof Error ? error.name : "UnknownError",
          messageCount: request.messages.length,
          model: request.model ?? null
        }
      });

      return err(
        toAppError(error, {
          code: "provider.execution_failed",
          message: `Provider execution failed: ${this.name}`,
          context: {
            providerName: this.name
          }
        })
      );
    }

    if (!decision.allowed) {
      await appendAuditEvent(this.auditContext, {
        sourcePackage: "@dominic-nexus/providers",
        action: "provider.call",
        decision: "denied",
        resource: {
          type: "provider",
          id: this.name,
          name: this.name
        },
        outcome: "denied",
        metadata: {
          decisionReason: decision.reason,
          messageCount: request.messages.length,
          model: request.model ?? null
        }
      });

      return err(
        new AppError({
          code: "provider.permission_denied",
          message: `Provider permission denied: ${this.name}`,
          context: {
            action: "provider.call",
            providerName: this.name
          }
        })
      );
    }

    const lastUserMessage = [...request.messages].reverse().find((message) => message.role === "user");
    await appendAuditEvent(this.auditContext, {
      sourcePackage: "@dominic-nexus/providers",
      action: "provider.call",
      decision: "allowed",
      resource: {
        type: "provider",
        id: this.name,
        name: this.name
      },
      outcome: "succeeded",
      metadata: {
        messageCount: request.messages.length,
        model: request.model ?? null
      }
    });

    return ok({
      message: {
        role: "assistant",
        content: lastUserMessage?.content ?? "Mock provider response."
      }
    });
  }

  async [providerRawChat](request: ChatRequest): Promise<ChatResponse> {
    const lastUserMessage = [...request.messages].reverse().find((message) => message.role === "user");

    return {
      message: {
        role: "assistant",
        content: lastUserMessage?.content ?? "Mock provider response."
      }
    };
  }

  async listModels(): Promise<Result<ProviderModel[]>> {
    return ok(this.models.map((model) => cloneModel(model)));
  }
}
