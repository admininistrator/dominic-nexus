import { appendAuditEvent, type OptionalAuditRuntimeContext } from "@dominic-nexus/audit";
import {
  AppError,
  err,
  ok,
  REDACTED_PLACEHOLDER,
  redactJsonRecord,
  type JsonObject,
  type JsonValue,
  type Result
} from "@dominic-nexus/shared";

export type PermissionAction =
  | "filesystem.read"
  | "filesystem.write"
  | "shell.execute"
  | "network.request"
  | "secret.read"
  | "memory.read"
  | "memory.write"
  | "plugin.execute"
  | "provider.call";

export interface PermissionRequest {
  action: PermissionAction;
  reason: string;
  resource?: string;
  metadata?: Record<string, JsonValue>;
}

export type PermissionDecisionKind = "allow" | "deny" | "approval-required";

export type PermissionApprovalState = "not-required" | "requested" | "user-approved" | "user-denied" | "invalid-response";

export interface PermissionApproval {
  state: PermissionApprovalState;
  promptRequired: boolean;
  response?: "allow" | "deny" | "invalid";
}

export interface PermissionDecision {
  allowed: boolean;
  kind?: PermissionDecisionKind;
  reason?: string;
  policySource?: string;
  approval?: PermissionApproval;
  auditMetadata?: Record<string, JsonValue>;
}

export type NormalizedPermissionDecision = PermissionDecision & {
  kind: PermissionDecisionKind;
  policySource: string;
};

export interface PolicyEngine {
  decide(request: PermissionRequest): PermissionDecision | Promise<PermissionDecision>;
}

export interface PermissionDecisionOptions {
  reason?: string;
  policySource: string;
  approval?: PermissionApproval;
  auditMetadata?: Record<string, JsonValue>;
}

export function allowPermissionDecision(options: PermissionDecisionOptions): NormalizedPermissionDecision {
  const decision: NormalizedPermissionDecision = {
    allowed: true,
    kind: "allow",
    policySource: options.policySource
  };

  if (options.reason !== undefined) {
    decision.reason = options.reason;
  }

  if (options.approval !== undefined) {
    decision.approval = options.approval;
  }

  if (options.auditMetadata !== undefined) {
    decision.auditMetadata = options.auditMetadata;
  }

  return decision;
}

export function denyPermissionDecision(options: PermissionDecisionOptions): NormalizedPermissionDecision {
  const decision: NormalizedPermissionDecision = {
    allowed: false,
    kind: "deny",
    policySource: options.policySource
  };

  if (options.reason !== undefined) {
    decision.reason = options.reason;
  }

  if (options.approval !== undefined) {
    decision.approval = options.approval;
  }

  if (options.auditMetadata !== undefined) {
    decision.auditMetadata = options.auditMetadata;
  }

  return decision;
}

export function approvalRequiredPermissionDecision(options: PermissionDecisionOptions): NormalizedPermissionDecision {
  return {
    ...denyPermissionDecision({
      ...options,
      approval: options.approval ?? {
        state: "requested",
        promptRequired: true
      }
    }),
    kind: "approval-required"
  };
}

export function normalizePermissionDecision(
  decision: PermissionDecision,
  fallbackPolicySource = "custom-policy"
): NormalizedPermissionDecision {
  return {
    ...decision,
    kind: decision.kind ?? (decision.allowed ? "allow" : "deny"),
    policySource: decision.policySource ?? fallbackPolicySource
  };
}

export function serializePermissionDecision(decision: PermissionDecision): JsonObject {
  const normalized = normalizePermissionDecision(decision);
  const serialized: JsonObject = {
    allowed: normalized.allowed,
    kind: normalized.kind,
    policySource: normalized.policySource
  };

  if (normalized.reason !== undefined) {
    serialized.reason = normalized.reason;
  }

  if (normalized.approval !== undefined) {
    serialized.approval = {
      ...normalized.approval
    };
  }

  if (normalized.auditMetadata !== undefined) {
    serialized.auditMetadata = redactJsonRecord(normalized.auditMetadata);
  }

  return serialized;
}

function sanitizeNetworkUrlForAudit(value: string): string {
  try {
    const parsed = new URL(value);
    parsed.username = "";
    parsed.password = "";
    parsed.search = "";
    parsed.hash = "";
    return parsed.href;
  } catch {
    return value;
  }
}

function sanitizeResourceForPermissionMetadata(action: PermissionAction, resource: string): string {
  if (action === "secret.read") {
    return REDACTED_PLACEHOLDER;
  }

  if (action === "network.request") {
    return sanitizeNetworkUrlForAudit(resource);
  }

  return resource;
}

function sanitizeNetworkRequestMetadata(metadata: Record<string, JsonValue>): Record<string, JsonValue> {
  const sanitized: Record<string, JsonValue> = {
    ...metadata
  };

  const networkRequest = sanitized.networkRequest;
  if (!isRecord(networkRequest)) {
    return sanitized;
  }

  const sanitizedNetworkRequest: JsonObject = {
    ...networkRequest
  };

  if (typeof sanitizedNetworkRequest.url === "string") {
    sanitizedNetworkRequest.url = sanitizeNetworkUrlForAudit(sanitizedNetworkRequest.url);
  }

  if (typeof sanitizedNetworkRequest.resource === "string") {
    sanitizedNetworkRequest.resource = sanitizeNetworkUrlForAudit(sanitizedNetworkRequest.resource);
  }

  sanitized.networkRequest = sanitizedNetworkRequest;
  return sanitized;
}

function sanitizeShellExecutionMetadata(metadata: Record<string, JsonValue>): Record<string, JsonValue> {
  const sanitized: Record<string, JsonValue> = {
    ...metadata
  };

  const shellExecutionRequest = sanitized.shellExecutionRequest;
  if (!isRecord(shellExecutionRequest)) {
    return sanitized;
  }

  const sanitizedShellRequest: JsonObject = {
    ...shellExecutionRequest
  };
  const env = sanitizedShellRequest.env;

  if (isRecord(env)) {
    sanitizedShellRequest.env = Object.fromEntries(
      Object.keys(env)
        .sort()
        .map((key) => [key, REDACTED_PLACEHOLDER])
    );
    sanitizedShellRequest.envKeys = Object.keys(env).sort();
  }

  sanitized.shellExecutionRequest = sanitizedShellRequest;
  return sanitized;
}

function sanitizeRequestMetadataForAudit(request: PermissionRequest): Record<string, JsonValue> {
  if (request.metadata === undefined) {
    return {};
  }

  if (request.action === "shell.execute") {
    return sanitizeShellExecutionMetadata(request.metadata);
  }

  if (request.action === "network.request") {
    return sanitizeNetworkRequestMetadata(request.metadata);
  }

  return request.metadata;
}

export async function decidePermissionWithAudit(
  policy: PolicyEngine,
  request: PermissionRequest,
  auditContext?: OptionalAuditRuntimeContext
): Promise<PermissionDecision> {
  const decision = normalizePermissionDecision(await policy.decide(request));

  const metadata: Record<string, unknown> = {
    reason: request.reason,
    allowed: decision.allowed,
    decisionKind: decision.kind,
    policySource: decision.policySource
  };

  if (request.resource !== undefined) {
    metadata.resource = sanitizeResourceForPermissionMetadata(request.action, request.resource);
  }

  if (decision.reason !== undefined) {
    metadata.decisionReason = decision.reason;
  }

  if (request.metadata !== undefined) {
    metadata.requestMetadata = redactJsonRecord(sanitizeRequestMetadataForAudit(request));
  }

  if (decision.approval !== undefined) {
    metadata.approval = decision.approval;
  }

  if (decision.auditMetadata !== undefined) {
    metadata.decisionMetadata = decision.auditMetadata;
  }

  const auditDecision = decision.kind === "allow" ? "allowed" : decision.kind === "deny" ? "denied" : "pending";
  const auditOutcome = decision.kind === "allow" ? "succeeded" : decision.kind === "deny" ? "denied" : "requested";

  await appendAuditEvent(auditContext, {
    sourcePackage: "@dominic-nexus/permissions",
    action: "permission.decide",
    decision: auditDecision,
    resource: {
      type: "permission",
      id: request.action,
      name: request.action
    },
    outcome: auditOutcome,
    metadata
  });

  return decision;
}

export function permissionDeniedError(request: PermissionRequest): AppError {
  const context: Record<string, JsonValue> = {
    action: request.action
  };

  if (request.resource !== undefined) {
    context.resource = sanitizeResourceForPermissionMetadata(request.action, request.resource);
  }

  return new AppError({
    code: "permission.denied",
    message: `Permission denied: ${request.action}`,
    context
  });
}

export interface ShellExecutionRequest {
  command: string;
  cwd?: string;
  env?: Record<string, string>;
  timeoutMs?: number;
}

export interface NormalizedShellExecutionRequest {
  command: string;
  cwd?: string;
  env: Record<string, string>;
  timeoutMs?: number;
}

export type ShellExecutionApprovalBinding = NormalizedShellExecutionRequest;

export interface ShellExecutionApproval {
  binding: ShellExecutionApprovalBinding;
  decision: NormalizedPermissionDecision;
  permissionRequest: PermissionRequest;
}

export interface ShellExecutionPermissionRequestOptions {
  reason?: string;
  metadata?: Record<string, JsonValue>;
}

export interface ShellPolicyAuthorizeOptions extends ShellExecutionPermissionRequestOptions {
  audit?: OptionalAuditRuntimeContext;
}

const SHELL_EXECUTION_REQUEST_KEYS = new Set(["command", "cwd", "env", "timeoutMs"]);

function shellInvalidRequest(message: string, context?: JsonObject): Result<never> {
  const options: {
    code: "shell.invalid_request";
    message: string;
    context?: JsonObject;
  } = {
    code: "shell.invalid_request",
    message
  };

  if (context !== undefined) {
    options.context = context;
  }

  return err(
    new AppError(options)
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function hasNonEmptyText(value: string): boolean {
  return value.trim().length > 0;
}

function containsNulByte(value: string): boolean {
  return value.includes("\0");
}

export function isRiskyShellEnvKey(key: string): boolean {
  const normalizedKey = key.toUpperCase();
  return normalizedKey === "PATH" || normalizedKey.startsWith("LD_") || normalizedKey.startsWith("DYLD_");
}

function validateShellEnv(value: unknown): Result<Record<string, string>> {
  if (value === undefined) {
    return ok({});
  }

  if (!isRecord(value)) {
    return shellInvalidRequest("Shell env must be an object with string values", {
      field: "env"
    });
  }

  const env: Record<string, string> = {};

  for (const key of Object.keys(value).sort()) {
    if (!hasNonEmptyText(key)) {
      return shellInvalidRequest("Shell env keys must be non-empty strings", {
        field: "env"
      });
    }

    if (containsNulByte(key)) {
      return shellInvalidRequest("Shell env keys must not contain NUL bytes", {
        field: "env",
        key
      });
    }

    if (isRiskyShellEnvKey(key)) {
      return shellInvalidRequest("Shell env contains a risky override", {
        field: "env",
        key
      });
    }

    const envValue = value[key];
    if (typeof envValue !== "string") {
      return shellInvalidRequest("Shell env values must be strings", {
        field: "env",
        key
      });
    }

    if (containsNulByte(envValue)) {
      return shellInvalidRequest("Shell env values must not contain NUL bytes", {
        field: "env",
        key
      });
    }

    env[key] = envValue;
  }

  return ok(env);
}

export function validateShellExecutionRequest(request: unknown): Result<NormalizedShellExecutionRequest> {
  if (!isRecord(request)) {
    return shellInvalidRequest("Shell execution request must be an object");
  }

  for (const key of Object.keys(request)) {
    if (!SHELL_EXECUTION_REQUEST_KEYS.has(key)) {
      return shellInvalidRequest("Shell execution request contains an unknown field", {
        field: key
      });
    }
  }

  if (typeof request.command !== "string" || !hasNonEmptyText(request.command)) {
    return shellInvalidRequest("Shell command must be a non-empty string", {
      field: "command"
    });
  }

  if (containsNulByte(request.command)) {
    return shellInvalidRequest("Shell command must not contain NUL bytes", {
      field: "command"
    });
  }

  const normalized: NormalizedShellExecutionRequest = {
    command: request.command,
    env: {}
  };

  if (request.cwd !== undefined) {
    if (typeof request.cwd !== "string" || !hasNonEmptyText(request.cwd)) {
      return shellInvalidRequest("Shell cwd must be a non-empty string when provided", {
        field: "cwd"
      });
    }

    if (containsNulByte(request.cwd)) {
      return shellInvalidRequest("Shell cwd must not contain NUL bytes", {
        field: "cwd"
      });
    }

    normalized.cwd = request.cwd;
  }

  const env = validateShellEnv(request.env);
  if (!env.ok) {
    return env;
  }

  normalized.env = env.value;

  if (request.timeoutMs !== undefined) {
    if (
      typeof request.timeoutMs !== "number" ||
      !Number.isFinite(request.timeoutMs) ||
      !Number.isInteger(request.timeoutMs) ||
      request.timeoutMs <= 0
    ) {
      return shellInvalidRequest("Shell timeoutMs must be a positive integer when provided", {
        field: "timeoutMs"
      });
    }

    normalized.timeoutMs = request.timeoutMs;
  }

  return ok(normalized);
}

export function createShellExecutionApprovalBinding(
  request: NormalizedShellExecutionRequest
): ShellExecutionApprovalBinding {
  const binding: ShellExecutionApprovalBinding = {
    command: request.command,
    env: Object.fromEntries(Object.entries(request.env).sort())
  };

  if (request.cwd !== undefined) {
    binding.cwd = request.cwd;
  }

  if (request.timeoutMs !== undefined) {
    binding.timeoutMs = request.timeoutMs;
  }

  return binding;
}

function shellExecutionApprovalBindingToJsonObject(binding: ShellExecutionApprovalBinding): JsonObject {
  const value: JsonObject = {
    command: binding.command,
    env: { ...binding.env }
  };

  if (binding.cwd !== undefined) {
    value.cwd = binding.cwd;
  }

  if (binding.timeoutMs !== undefined) {
    value.timeoutMs = binding.timeoutMs;
  }

  return value;
}

function shellExecutionBindingsEqual(
  left: ShellExecutionApprovalBinding,
  right: ShellExecutionApprovalBinding
): boolean {
  if (left.command !== right.command || left.cwd !== right.cwd || left.timeoutMs !== right.timeoutMs) {
    return false;
  }

  const leftEnvEntries = Object.entries(left.env);
  const rightEnvEntries = Object.entries(right.env);
  if (leftEnvEntries.length !== rightEnvEntries.length) {
    return false;
  }

  return leftEnvEntries.every(([key, value]) => right.env[key] === value);
}

export function createShellExecutionPermissionRequest(
  request: NormalizedShellExecutionRequest,
  options: ShellExecutionPermissionRequestOptions = {}
): PermissionRequest {
  const binding = createShellExecutionApprovalBinding(request);
  const metadata: Record<string, JsonValue> = {
    ...(options.metadata ?? {}),
    shellExecutionRequest: shellExecutionApprovalBindingToJsonObject(binding)
  };

  return {
    action: "shell.execute",
    reason: options.reason ?? "Execute shell command",
    resource: request.command,
    metadata
  };
}

export function createShellExecutionApproval(
  request: NormalizedShellExecutionRequest,
  decision: PermissionDecision,
  permissionRequest = createShellExecutionPermissionRequest(request)
): ShellExecutionApproval {
  return {
    binding: createShellExecutionApprovalBinding(request),
    decision: normalizePermissionDecision(decision),
    permissionRequest
  };
}

export function isShellExecutionApprovalBoundToRequest(
  approval: ShellExecutionApproval,
  request: NormalizedShellExecutionRequest
): boolean {
  return shellExecutionBindingsEqual(approval.binding, createShellExecutionApprovalBinding(request));
}

export class ShellPolicy {
  constructor(private readonly policy: PolicyEngine) {}

  async authorize(
    request: unknown,
    options: ShellPolicyAuthorizeOptions = {}
  ): Promise<Result<ShellExecutionApproval>> {
    const normalizedRequest = validateShellExecutionRequest(request);
    if (!normalizedRequest.ok) {
      return normalizedRequest;
    }

    const permissionRequest = createShellExecutionPermissionRequest(normalizedRequest.value, options);
    const decision = normalizePermissionDecision(await decidePermissionWithAudit(this.policy, permissionRequest, options.audit));

    if (!decision.allowed) {
      return err(
        new AppError({
          code: "permission.denied",
          message: "Shell execution permission denied",
          context: {
            action: "shell.execute",
            command: normalizedRequest.value.command
          }
        })
      );
    }

    return ok(createShellExecutionApproval(normalizedRequest.value, decision, permissionRequest));
  }
}

export interface NetworkRequest {
  url?: string;
  resource?: string;
  host?: string;
  protocol?: string;
  method?: string;
  headers?: Record<string, string>;
}

export interface NormalizedNetworkRequest {
  url?: string;
  resource?: string;
  host?: string;
  protocol?: string;
  method?: string;
  headers: Record<string, string>;
}

export type NetworkRequestApprovalBinding = NormalizedNetworkRequest;

export interface NetworkRequestApproval {
  binding: NetworkRequestApprovalBinding;
  decision: NormalizedPermissionDecision;
  permissionRequest: PermissionRequest;
}

export interface NetworkRequestPermissionRequestOptions {
  reason?: string;
  metadata?: Record<string, JsonValue>;
}

export interface NetworkPolicyAuthorizeOptions extends NetworkRequestPermissionRequestOptions {
  audit?: OptionalAuditRuntimeContext;
}

const NETWORK_REQUEST_KEYS = new Set(["url", "resource", "host", "protocol", "method", "headers"]);
const NETWORK_PROTOCOLS = new Set(["http:", "https:", "ws:", "wss:"]);

function networkInvalidRequest(message: string, context?: JsonObject): Result<never> {
  const options: {
    code: "network.invalid_request";
    message: string;
    context?: JsonObject;
  } = {
    code: "network.invalid_request",
    message
  };

  if (context !== undefined) {
    options.context = context;
  }

  return err(
    new AppError(options)
  );
}

function validateNetworkString(value: unknown, field: string): Result<string | undefined> {
  if (value === undefined) {
    return ok(undefined);
  }

  if (typeof value !== "string" || !hasNonEmptyText(value)) {
    return networkInvalidRequest("Network request field must be a non-empty string when provided", {
      field
    });
  }

  if (containsNulByte(value)) {
    return networkInvalidRequest("Network request field must not contain NUL bytes", {
      field
    });
  }

  return ok(value.trim());
}

function normalizeNetworkProtocol(value: string): Result<string> {
  const protocol = value.endsWith(":") ? value.toLowerCase() : `${value.toLowerCase()}:`;

  if (!NETWORK_PROTOCOLS.has(protocol)) {
    return networkInvalidRequest("Network request protocol is not allowed", {
      field: "protocol",
      protocol
    });
  }

  return ok(protocol);
}

function parseNetworkUrl(value: string): Result<URL> {
  let parsed: URL;

  try {
    parsed = new URL(value);
  } catch {
    return networkInvalidRequest("Network request url must be a valid URL", {
      field: "url"
    });
  }

  if (!NETWORK_PROTOCOLS.has(parsed.protocol)) {
    return networkInvalidRequest("Network request url protocol is not allowed", {
      field: "url",
      protocol: parsed.protocol
    });
  }

  return ok(parsed);
}

function validateNetworkMethod(value: unknown): Result<string | undefined> {
  if (value === undefined) {
    return ok(undefined);
  }

  if (typeof value !== "string" || !hasNonEmptyText(value)) {
    return networkInvalidRequest("Network request method must be a non-empty string when provided", {
      field: "method"
    });
  }

  if (containsNulByte(value) || /\s/u.test(value)) {
    return networkInvalidRequest("Network request method must not contain whitespace or NUL bytes", {
      field: "method"
    });
  }

  return ok(value.toUpperCase());
}

function validateNetworkHeaders(value: unknown): Result<Record<string, string>> {
  if (value === undefined) {
    return ok({});
  }

  if (!isRecord(value)) {
    return networkInvalidRequest("Network request headers must be an object with string values", {
      field: "headers"
    });
  }

  const headers: Record<string, string> = {};

  for (const key of Object.keys(value).sort()) {
    if (!hasNonEmptyText(key)) {
      return networkInvalidRequest("Network request header names must be non-empty strings", {
        field: "headers"
      });
    }

    if (containsNulByte(key)) {
      return networkInvalidRequest("Network request header names must not contain NUL bytes", {
        field: "headers",
        header: key
      });
    }

    const headerValue = value[key];
    if (typeof headerValue !== "string") {
      return networkInvalidRequest("Network request header values must be strings", {
        field: "headers",
        header: key
      });
    }

    if (containsNulByte(headerValue)) {
      return networkInvalidRequest("Network request header values must not contain NUL bytes", {
        field: "headers",
        header: key
      });
    }

    headers[key] = headerValue;
  }

  return ok(headers);
}

export function validateNetworkRequest(request: unknown): Result<NormalizedNetworkRequest> {
  if (!isRecord(request)) {
    return networkInvalidRequest("Network request must be an object");
  }

  for (const key of Object.keys(request)) {
    if (!NETWORK_REQUEST_KEYS.has(key)) {
      return networkInvalidRequest("Network request contains an unknown field", {
        field: key
      });
    }
  }

  const url = validateNetworkString(request.url, "url");
  if (!url.ok) {
    return url;
  }

  const resource = validateNetworkString(request.resource, "resource");
  if (!resource.ok) {
    return resource;
  }

  const host = validateNetworkString(request.host, "host");
  if (!host.ok) {
    return host;
  }

  const protocol = validateNetworkString(request.protocol, "protocol");
  if (!protocol.ok) {
    return protocol;
  }

  if (url.value === undefined && resource.value === undefined && host.value === undefined) {
    return networkInvalidRequest("Network request must include url, resource, or host");
  }

  const normalized: NormalizedNetworkRequest = {
    headers: {}
  };

  let parsedUrl: URL | undefined;
  if (url.value !== undefined) {
    const parsed = parseNetworkUrl(url.value);
    if (!parsed.ok) {
      return parsed;
    }

    parsedUrl = parsed.value;
    normalized.url = parsedUrl.href;
    normalized.host = parsedUrl.host;
    normalized.protocol = parsedUrl.protocol;
  }

  if (resource.value !== undefined) {
    normalized.resource = resource.value;
  }

  if (host.value !== undefined) {
    const normalizedHost = host.value.toLowerCase();

    if (parsedUrl !== undefined && normalizedHost !== parsedUrl.host) {
      return networkInvalidRequest("Network request host must match the provided URL", {
        field: "host",
        host: normalizedHost,
        urlHost: parsedUrl.host
      });
    }

    normalized.host = normalizedHost;
  }

  if (protocol.value !== undefined) {
    const normalizedProtocol = normalizeNetworkProtocol(protocol.value);
    if (!normalizedProtocol.ok) {
      return normalizedProtocol;
    }

    if (parsedUrl !== undefined && normalizedProtocol.value !== parsedUrl.protocol) {
      return networkInvalidRequest("Network request protocol must match the provided URL", {
        field: "protocol",
        protocol: normalizedProtocol.value,
        urlProtocol: parsedUrl.protocol
      });
    }

    normalized.protocol = normalizedProtocol.value;
  }

  const method = validateNetworkMethod(request.method);
  if (!method.ok) {
    return method;
  }

  if (method.value !== undefined) {
    normalized.method = method.value;
  }

  const headers = validateNetworkHeaders(request.headers);
  if (!headers.ok) {
    return headers;
  }

  normalized.headers = headers.value;

  return ok(normalized);
}

export function createNetworkRequestApprovalBinding(
  request: NormalizedNetworkRequest
): NetworkRequestApprovalBinding {
  const binding: NetworkRequestApprovalBinding = {
    headers: Object.fromEntries(Object.entries(request.headers).sort())
  };

  if (request.url !== undefined) {
    binding.url = request.url;
  }

  if (request.resource !== undefined) {
    binding.resource = request.resource;
  }

  if (request.host !== undefined) {
    binding.host = request.host;
  }

  if (request.protocol !== undefined) {
    binding.protocol = request.protocol;
  }

  if (request.method !== undefined) {
    binding.method = request.method;
  }

  return binding;
}

function networkRequestApprovalBindingToJsonObject(binding: NetworkRequestApprovalBinding): JsonObject {
  const value: JsonObject = {
    headers: { ...binding.headers }
  };

  if (binding.url !== undefined) {
    value.url = binding.url;
  }

  if (binding.resource !== undefined) {
    value.resource = binding.resource;
  }

  if (binding.host !== undefined) {
    value.host = binding.host;
  }

  if (binding.protocol !== undefined) {
    value.protocol = binding.protocol;
  }

  if (binding.method !== undefined) {
    value.method = binding.method;
  }

  return value;
}

function networkRequestBindingsEqual(
  left: NetworkRequestApprovalBinding,
  right: NetworkRequestApprovalBinding
): boolean {
  if (
    left.url !== right.url ||
    left.resource !== right.resource ||
    left.host !== right.host ||
    left.protocol !== right.protocol ||
    left.method !== right.method
  ) {
    return false;
  }

  const leftHeaderEntries = Object.entries(left.headers);
  const rightHeaderEntries = Object.entries(right.headers);
  if (leftHeaderEntries.length !== rightHeaderEntries.length) {
    return false;
  }

  return leftHeaderEntries.every(([key, value]) => right.headers[key] === value);
}

function getNetworkRequestPermissionResource(request: NormalizedNetworkRequest): string {
  return sanitizeNetworkUrlForAudit(request.resource ?? request.url ?? request.host ?? "network.request");
}

export function createNetworkRequestPermissionRequest(
  request: NormalizedNetworkRequest,
  options: NetworkRequestPermissionRequestOptions = {}
): PermissionRequest {
  const binding = createNetworkRequestApprovalBinding(request);
  const metadata: Record<string, JsonValue> = {
    ...(options.metadata ?? {}),
    networkRequest: networkRequestApprovalBindingToJsonObject(binding)
  };

  return {
    action: "network.request",
    reason: options.reason ?? "Perform network request",
    resource: getNetworkRequestPermissionResource(request),
    metadata
  };
}

export function createNetworkRequestApproval(
  request: NormalizedNetworkRequest,
  decision: PermissionDecision,
  permissionRequest = createNetworkRequestPermissionRequest(request)
): NetworkRequestApproval {
  return {
    binding: createNetworkRequestApprovalBinding(request),
    decision: normalizePermissionDecision(decision),
    permissionRequest
  };
}

export function isNetworkRequestApprovalBoundToRequest(
  approval: NetworkRequestApproval,
  request: NormalizedNetworkRequest
): boolean {
  return networkRequestBindingsEqual(approval.binding, createNetworkRequestApprovalBinding(request));
}

export class NetworkPolicy {
  constructor(private readonly policy: PolicyEngine) {}

  async authorize(
    request: unknown,
    options: NetworkPolicyAuthorizeOptions = {}
  ): Promise<Result<NetworkRequestApproval>> {
    const normalizedRequest = validateNetworkRequest(request);
    if (!normalizedRequest.ok) {
      return normalizedRequest;
    }

    const permissionRequest = createNetworkRequestPermissionRequest(normalizedRequest.value, options);
    const decision = normalizePermissionDecision(await decidePermissionWithAudit(this.policy, permissionRequest, options.audit));

    if (!decision.allowed) {
      return err(
        new AppError({
          code: "permission.denied",
          message: "Network request permission denied",
          context: {
            action: "network.request",
            resource: getNetworkRequestPermissionResource(normalizedRequest.value)
          }
        })
      );
    }

    return ok(createNetworkRequestApproval(normalizedRequest.value, decision, permissionRequest));
  }
}

export interface ApprovalPromptRequest {
  action: PermissionAction;
  reason: string;
  resource?: string;
}

export type ApprovalPrompt = (request: ApprovalPromptRequest) => string | Promise<string>;

export interface InteractiveApprovalPolicyOptions {
  prompt: ApprovalPrompt;
}

const RISKY_ACTIONS = new Set<PermissionAction>([
  "filesystem.write",
  "shell.execute",
  "network.request",
  "secret.read",
  "provider.call",
  "plugin.execute"
]);

export class DefaultDenyPolicy implements PolicyEngine {
  decide(request: PermissionRequest): PermissionDecision {
    return denyPermissionDecision({
      policySource: "default-deny",
      reason: `Denied by default policy: ${request.action}`
    });
  }
}

export class AllowAllDevelopmentPolicy implements PolicyEngine {
  decide(): PermissionDecision {
    return allowPermissionDecision({
      policySource: "allow-all-development",
      reason: "Allowed by development policy"
    });
  }
}

export class InteractiveApprovalPolicy implements PolicyEngine {
  constructor(private readonly options: InteractiveApprovalPolicyOptions) {}

  async decide(request: PermissionRequest): Promise<PermissionDecision> {
    if (!RISKY_ACTIONS.has(request.action)) {
      return allowPermissionDecision({
        policySource: "interactive-approval",
        reason: `Allowed without approval: ${request.action}`,
        approval: {
          state: "not-required",
          promptRequired: false
        },
        auditMetadata: {
          risky: false
        }
      });
    }

    const promptRequest: ApprovalPromptRequest = {
      action: request.action,
      reason: request.reason
    };

    if (request.resource !== undefined) {
      promptRequest.resource = request.resource;
    }

    const answer = (await this.options.prompt(promptRequest)).trim().toLowerCase();

    if (answer === "y" || answer === "yes" || answer === "allow") {
      return allowPermissionDecision({
        policySource: "interactive-approval",
        reason: `Approved by user: ${request.action}`,
        approval: {
          state: "user-approved",
          promptRequired: true,
          response: "allow"
        },
        auditMetadata: {
          risky: true
        }
      });
    }

    if (answer === "n" || answer === "no" || answer === "deny") {
      return denyPermissionDecision({
        policySource: "interactive-approval",
        reason: `Denied by user: ${request.action}`,
        approval: {
          state: "user-denied",
          promptRequired: true,
          response: "deny"
        },
        auditMetadata: {
          risky: true
        }
      });
    }

    return denyPermissionDecision({
      policySource: "interactive-approval",
      reason: `Denied by default after invalid approval response: ${request.action}`,
      approval: {
        state: "invalid-response",
        promptRequired: true,
        response: "invalid"
      },
      auditMetadata: {
        risky: true
      }
    });
  }
}
