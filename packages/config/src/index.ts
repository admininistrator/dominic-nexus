import { mkdirSync, readFileSync, renameSync, unlinkSync, writeFileSync } from "node:fs";
import path from "node:path";
import { appendAuditEvent, type OptionalAuditRuntimeContext } from "@dominic-nexus/audit";
import {
  AppError,
  REDACTED_PLACEHOLDER,
  err,
  isJsonObject,
  ok,
  type JsonObject,
  type JsonValue,
  type Result
} from "@dominic-nexus/shared";

export type LogLevel = "debug" | "info" | "warn" | "error";

export interface ConfigSecretRef {
  provider: "env";
  key: string;
}

export interface SourceConfig {
  appName?: string;
  environment?: string;
  logLevel?: LogLevel;
  secrets?: Record<string, ConfigSecretRef>;
  stateDirectory?: string;
}

export interface RuntimeConfig {
  appName: string;
  environment: string;
  logLevel: LogLevel;
  secrets?: Record<string, ConfigSecretRef>;
  stateDirectory: string;
  configFilePath?: string;
}

export type AppConfig = RuntimeConfig;

export interface LoadConfigOptions {
  env?: NodeJS.ProcessEnv;
  configFilePath?: string;
  readFile?: (path: string) => string;
}

interface NormalizedLoadConfigOptions {
  env: NodeJS.ProcessEnv;
  configFilePath: string | undefined;
  readFile: (path: string) => string;
}

export const CONFIG_ENVIRONMENT_OVERRIDES = [
  "DOMINIC_NEXUS_CONFIG_PATH",
  "DOMINIC_NEXUS_APP_NAME",
  "DOMINIC_NEXUS_STATE_DIRECTORY",
  "DOMINIC_NEXUS_LOG_LEVEL",
  "NODE_ENV"
] as const;

const LOG_LEVELS = ["debug", "info", "warn", "error"] as const;
const LOG_LEVEL_SET = new Set<LogLevel>(LOG_LEVELS);
const SOURCE_CONFIG_KEYS = new Set(["appName", "environment", "logLevel", "secrets", "stateDirectory"]);
const SECRET_REF_KEYS = new Set(["provider", "key"]);
type ConfigEnvironmentOverride = (typeof CONFIG_ENVIRONMENT_OVERRIDES)[number];
type SourceConfigEnvironmentOverride = Exclude<ConfigEnvironmentOverride, "DOMINIC_NEXUS_CONFIG_PATH">;
export type SourceConfigKey = keyof SourceConfig;

const SOURCE_CONFIG_ENVIRONMENT_OVERRIDE_MAP = {
  DOMINIC_NEXUS_APP_NAME: "appName",
  DOMINIC_NEXUS_STATE_DIRECTORY: "stateDirectory",
  DOMINIC_NEXUS_LOG_LEVEL: "logLevel",
  NODE_ENV: "environment"
} as const satisfies Record<SourceConfigEnvironmentOverride, keyof SourceConfig>;

const DEFAULT_SOURCE_CONFIG: Required<Pick<SourceConfig, "appName" | "environment" | "logLevel" | "stateDirectory">> = {
  appName: "Dominic Nexus",
  environment: "development",
  logLevel: "info",
  stateDirectory: ".dominic-nexus/state"
};

export function parseLogLevel(value: string | undefined): Result<LogLevel> {
  if (value === undefined) {
    return ok("info");
  }

  if (LOG_LEVEL_SET.has(value as LogLevel)) {
    return ok(value as LogLevel);
  }

  return err(
    new AppError({
      code: "config.invalid",
      message: "Invalid DOMINIC_NEXUS_LOG_LEVEL",
      context: {
        variable: "DOMINIC_NEXUS_LOG_LEVEL",
        allowedValues: [...LOG_LEVELS]
      }
    })
  );
}

function configInvalid(message: string, context?: JsonObject): Result<never> {
  const errorOptions =
    context === undefined
      ? {
          code: "config.invalid" as const,
          message
        }
      : {
          code: "config.invalid" as const,
          message,
          context
        };

  return err(new AppError(errorOptions));
}

function configWriteDenied(message: string, context?: JsonObject): Result<never> {
  const errorOptions =
    context === undefined
      ? {
          code: "config.write_denied" as const,
          message
        }
      : {
          code: "config.write_denied" as const,
          message,
          context
        };

  return err(new AppError(errorOptions));
}

function configWriteFailed(message: string, context?: JsonObject): Result<never> {
  const errorOptions =
    context === undefined
      ? {
          code: "config.write_failed" as const,
          message
        }
      : {
          code: "config.write_failed" as const,
          message,
          context
        };

  return err(new AppError(errorOptions));
}

function cloneSourceConfig(source: SourceConfig): SourceConfig {
  return JSON.parse(JSON.stringify(source)) as SourceConfig;
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0;
}

function validateOptionalString(
  source: JsonObject,
  key: "appName" | "environment" | "stateDirectory",
  label: string
): Result<string | undefined> {
  if (source[key] === undefined) {
    return ok(undefined);
  }

  if (!isNonEmptyString(source[key])) {
    return configInvalid(`${label} must be a non-empty string`, {
      field: key
    });
  }

  return ok(source[key]);
}

function validateSecretRef(value: unknown, name: string): Result<ConfigSecretRef> {
  if (!isJsonObject(value)) {
    return configInvalid("SecretRef must be a JSON object", {
      field: `secrets.${name}`
    });
  }

  const unknownKeys = Object.keys(value).filter((key) => !SECRET_REF_KEYS.has(key));
  if (unknownKeys.length > 0) {
    return configInvalid("SecretRef contains unknown keys", {
      field: `secrets.${name}`,
      unknownKeys
    });
  }

  if (value.provider !== "env") {
    return configInvalid("SecretRef provider must be env", {
      field: `secrets.${name}.provider`
    });
  }

  if (!isNonEmptyString(value.key)) {
    return configInvalid("SecretRef key must be a non-empty string", {
      field: `secrets.${name}.key`
    });
  }

  return ok({
    provider: "env",
    key: value.key
  });
}

function validateSecrets(value: unknown): Result<Record<string, ConfigSecretRef> | undefined> {
  if (value === undefined) {
    return ok(undefined);
  }

  if (!isJsonObject(value)) {
    return configInvalid("secrets must be a JSON object", {
      field: "secrets"
    });
  }

  const secrets: Record<string, ConfigSecretRef> = {};

  for (const [name, secretRef] of Object.entries(value)) {
    if (!isNonEmptyString(name)) {
      return configInvalid("Secret name must be a non-empty string", {
        field: "secrets"
      });
    }

    const parsedSecretRef = validateSecretRef(secretRef, name);
    if (!parsedSecretRef.ok) {
      return parsedSecretRef;
    }

    secrets[name] = parsedSecretRef.value;
  }

  return ok(secrets);
}

export function parseSourceConfig(value: unknown): Result<SourceConfig> {
  if (!isJsonObject(value)) {
    return configInvalid("Config source must be a JSON object");
  }

  const unknownKeys = Object.keys(value).filter((key) => !SOURCE_CONFIG_KEYS.has(key));
  if (unknownKeys.length > 0) {
    return configInvalid("Config source contains unknown keys", {
      unknownKeys
    });
  }

  const appName = validateOptionalString(value, "appName", "appName");
  if (!appName.ok) {
    return appName;
  }

  const environment = validateOptionalString(value, "environment", "environment");
  if (!environment.ok) {
    return environment;
  }

  const stateDirectory = validateOptionalString(value, "stateDirectory", "stateDirectory");
  if (!stateDirectory.ok) {
    return stateDirectory;
  }

  if (stateDirectory.value !== undefined && stateDirectory.value.includes("\0")) {
    return configInvalid("stateDirectory must not contain NUL bytes", {
      field: "stateDirectory"
    });
  }

  const logLevelValue = value.logLevel;
  if (logLevelValue !== undefined) {
    if (typeof logLevelValue !== "string" || !LOG_LEVEL_SET.has(logLevelValue as LogLevel)) {
      return configInvalid("logLevel must be one of the allowed values", {
        field: "logLevel",
        allowedValues: [...LOG_LEVELS]
      });
    }
  }

  const secrets = validateSecrets(value.secrets);
  if (!secrets.ok) {
    return secrets;
  }

  const parsed: SourceConfig = {};

  if (appName.value !== undefined) {
    parsed.appName = appName.value;
  }

  if (environment.value !== undefined) {
    parsed.environment = environment.value;
  }

  if (stateDirectory.value !== undefined) {
    parsed.stateDirectory = stateDirectory.value;
  }

  if (logLevelValue !== undefined) {
    parsed.logLevel = logLevelValue as LogLevel;
  }

  if (secrets.value !== undefined) {
    parsed.secrets = secrets.value;
  }

  return ok(parsed);
}

export function applyRuntimeDefaults(source: SourceConfig, configFilePath?: string): RuntimeConfig {
  const runtime: RuntimeConfig = {
    appName: source.appName ?? DEFAULT_SOURCE_CONFIG.appName,
    environment: source.environment ?? DEFAULT_SOURCE_CONFIG.environment,
    logLevel: source.logLevel ?? DEFAULT_SOURCE_CONFIG.logLevel,
    stateDirectory: source.stateDirectory ?? DEFAULT_SOURCE_CONFIG.stateDirectory
  };

  if (source.secrets !== undefined) {
    runtime.secrets = JSON.parse(JSON.stringify(source.secrets)) as Record<string, ConfigSecretRef>;
  }

  if (configFilePath !== undefined) {
    runtime.configFilePath = configFilePath;
  }

  return runtime;
}

export function applyEnvironmentOverrides(source: SourceConfig, env: NodeJS.ProcessEnv): Result<SourceConfig> {
  const parsedSource = parseSourceConfig(source);
  if (!parsedSource.ok) {
    return parsedSource;
  }

  const overrides: JsonObject = {};

  for (const envKey of Object.keys(SOURCE_CONFIG_ENVIRONMENT_OVERRIDE_MAP) as SourceConfigEnvironmentOverride[]) {
    const value = env[envKey];
    if (value !== undefined) {
      overrides[SOURCE_CONFIG_ENVIRONMENT_OVERRIDE_MAP[envKey]] = value;
    }
  }

  const parsedOverrides = parseSourceConfig(overrides);
  if (!parsedOverrides.ok) {
    return parsedOverrides;
  }

  return parseSourceConfig({
    ...parsedSource.value,
    ...parsedOverrides.value
  });
}

function normalizeSourceConfigKey(key: string): Result<SourceConfigKey> {
  if (SOURCE_CONFIG_KEYS.has(key)) {
    return ok(key as SourceConfigKey);
  }

  return configInvalid("Config key is unknown", {
    field: key
  });
}

function containsRedactedPlaceholder(value: unknown): boolean {
  if (value === REDACTED_PLACEHOLDER) {
    return true;
  }

  if (Array.isArray(value)) {
    return value.some((item) => containsRedactedPlaceholder(item));
  }

  if (value !== null && typeof value === "object") {
    return Object.values(value).some((item) => containsRedactedPlaceholder(item));
  }

  return false;
}

function validateWritableSourceConfig(value: unknown): Result<SourceConfig> {
  if (containsRedactedPlaceholder(value)) {
    return configInvalid("Config values must not contain redacted placeholders", {
      placeholder: REDACTED_PLACEHOLDER
    });
  }

  return parseSourceConfig(value);
}

export function getSourceConfigValue(source: SourceConfig, key: string): Result<SourceConfig[SourceConfigKey] | undefined> {
  const parsedSource = parseSourceConfig(source);
  if (!parsedSource.ok) {
    return parsedSource;
  }

  const parsedKey = normalizeSourceConfigKey(key);
  if (!parsedKey.ok) {
    return parsedKey;
  }

  return ok(parsedSource.value[parsedKey.value]);
}

export function setSourceConfigValue(source: SourceConfig, key: string, value: unknown): Result<SourceConfig> {
  const parsedSource = parseSourceConfig(source);
  if (!parsedSource.ok) {
    return parsedSource;
  }

  const parsedKey = normalizeSourceConfigKey(key);
  if (!parsedKey.ok) {
    return parsedKey;
  }

  return validateWritableSourceConfig({
    ...cloneSourceConfig(parsedSource.value),
    [parsedKey.value]: value
  });
}

export function unsetSourceConfigValue(source: SourceConfig, key: string): Result<SourceConfig> {
  const parsedSource = parseSourceConfig(source);
  if (!parsedSource.ok) {
    return parsedSource;
  }

  const parsedKey = normalizeSourceConfigKey(key);
  if (!parsedKey.ok) {
    return parsedKey;
  }

  const next = cloneSourceConfig(parsedSource.value);
  delete next[parsedKey.value];

  return validateWritableSourceConfig(next);
}

export function mergeSourceConfig(source: SourceConfig, patch: unknown): Result<SourceConfig> {
  const parsedSource = parseSourceConfig(source);
  if (!parsedSource.ok) {
    return parsedSource;
  }

  const parsedPatch = validateWritableSourceConfig(patch);
  if (!parsedPatch.ok) {
    return parsedPatch;
  }

  return validateWritableSourceConfig({
    ...cloneSourceConfig(parsedSource.value),
    ...cloneSourceConfig(parsedPatch.value)
  });
}

export function replaceSourceConfig(next: unknown): Result<SourceConfig> {
  return validateWritableSourceConfig(next);
}

export interface ConfigWriteAuthorizationRequest {
  path: string;
  reason: string;
  metadata: Record<string, JsonValue>;
}

export type ConfigWriteAuthorizer = (
  request: ConfigWriteAuthorizationRequest
) => Result<unknown> | Promise<Result<unknown>>;

export interface ConfigFileAccess {
  mkdir(path: string): void;
  readFile(path: string): string;
  rename(fromPath: string, toPath: string): void;
  unlink(path: string): void;
  writeFile(path: string, content: string): void;
}

export interface WriteSourceConfigFileOptions {
  configFilePath: string;
  sourceConfig: SourceConfig;
  authorizeWrite: ConfigWriteAuthorizer;
  access?: ConfigFileAccess;
  audit?: OptionalAuditRuntimeContext;
  reason?: string;
  tempFilePath?: string;
}

export interface ReadSourceConfigFileOptions {
  configFilePath: string;
  readFile?: (path: string) => string;
}

export interface EditSourceConfigFileOptions {
  configFilePath: string;
  authorizeWrite: ConfigWriteAuthorizer;
  edit: (source: SourceConfig) => Result<SourceConfig>;
  access?: ConfigFileAccess;
  audit?: OptionalAuditRuntimeContext;
  reason?: string;
  tempFilePath?: string;
}

const DEFAULT_CONFIG_FILE_ACCESS: ConfigFileAccess = {
  mkdir(dirPath) {
    mkdirSync(dirPath, {
      recursive: true
    });
  },
  readFile(filePath) {
    return readFileSync(filePath, "utf8");
  },
  rename(fromPath, toPath) {
    renameSync(fromPath, toPath);
  },
  unlink(filePath) {
    unlinkSync(filePath);
  },
  writeFile(filePath, content) {
    writeFileSync(filePath, content, "utf8");
  }
};

function getSourceConfigFields(source: SourceConfig): string[] {
  return Object.keys(source).sort();
}

function createConfigWriteMetadata(operation: string, source: SourceConfig): Record<string, JsonValue> {
  return {
    operation,
    fields: getSourceConfigFields(source)
  };
}

function serializeSourceConfig(source: SourceConfig): string {
  return `${JSON.stringify(source, null, 2)}\n`;
}

function createTempConfigFilePath(configFilePath: string): string {
  const directory = path.dirname(configFilePath);
  const baseName = path.basename(configFilePath);
  return path.join(directory, `.${baseName}.${process.pid}.${Date.now()}.tmp`);
}

async function auditConfigWrite(
  audit: OptionalAuditRuntimeContext | undefined,
  options: {
    path: string;
    decision: "allowed" | "denied" | "not_applicable";
    outcome: "succeeded" | "failed" | "denied";
    metadata: Record<string, JsonValue>;
  }
): Promise<void> {
  await appendAuditEvent(audit, {
    sourcePackage: "@dominic-nexus/config",
    action: "config.write",
    decision: options.decision,
    resource: {
      type: "config_file",
      id: options.path,
      name: options.path
    },
    outcome: options.outcome,
    metadata: options.metadata
  });
}

export function readSourceConfigFileResult(options: ReadSourceConfigFileOptions): Result<SourceConfig> {
  const normalizedPath = normalizeExplicitConfigFilePath(options.configFilePath);
  if (!normalizedPath.ok) {
    return normalizedPath;
  }

  if (normalizedPath.value === undefined) {
    return configInvalid("configFilePath must be a non-empty string", {
      field: "configFilePath"
    });
  }

  return readSourceConfigFile(normalizedPath.value, options.readFile ?? ((filePath) => readFileSync(filePath, "utf8")));
}

export async function writeSourceConfigFileResult(options: WriteSourceConfigFileOptions): Promise<Result<SourceConfig>> {
  const normalizedPath = normalizeExplicitConfigFilePath(options.configFilePath);
  if (!normalizedPath.ok) {
    return normalizedPath;
  }

  if (normalizedPath.value === undefined) {
    return configInvalid("configFilePath must be a non-empty string", {
      field: "configFilePath"
    });
  }

  const parsedConfig = replaceSourceConfig(options.sourceConfig);
  if (!parsedConfig.ok) {
    return parsedConfig;
  }

  const metadata = createConfigWriteMetadata("replace", parsedConfig.value);
  let authorization: Result<unknown>;

  try {
    authorization = await options.authorizeWrite({
      path: normalizedPath.value,
      reason: options.reason ?? "Write Dominic Nexus config",
      metadata
    });
  } catch (error) {
    await auditConfigWrite(options.audit, {
      path: normalizedPath.value,
      decision: "not_applicable",
      outcome: "failed",
      metadata: {
        ...metadata,
        errorName: error instanceof Error ? error.name : "UnknownError"
      }
    });

    return configWriteDenied("Config write authorization failed", {
      path: normalizedPath.value
    });
  }

  if (!authorization.ok) {
    await auditConfigWrite(options.audit, {
      path: normalizedPath.value,
      decision: "denied",
      outcome: "denied",
      metadata
    });

    return err(authorization.error);
  }

  const access = options.access ?? DEFAULT_CONFIG_FILE_ACCESS;
  const tempFilePath = options.tempFilePath ?? createTempConfigFilePath(normalizedPath.value);

  try {
    access.mkdir(path.dirname(normalizedPath.value));
    access.writeFile(tempFilePath, serializeSourceConfig(parsedConfig.value));
    access.rename(tempFilePath, normalizedPath.value);

    await auditConfigWrite(options.audit, {
      path: normalizedPath.value,
      decision: "allowed",
      outcome: "succeeded",
      metadata
    });

    return ok(parsedConfig.value);
  } catch (error) {
    try {
      access.unlink(tempFilePath);
    } catch {
      // Best-effort cleanup after a failed authorized write.
    }

    await auditConfigWrite(options.audit, {
      path: normalizedPath.value,
      decision: "allowed",
      outcome: "failed",
      metadata: {
        ...metadata,
        errorName: error instanceof Error ? error.name : "UnknownError"
      }
    });

    return configWriteFailed("Config file could not be written", {
      path: normalizedPath.value,
      errorName: error instanceof Error ? error.name : "UnknownError"
    });
  }
}

export async function editSourceConfigFileResult(options: EditSourceConfigFileOptions): Promise<Result<SourceConfig>> {
  const access = options.access ?? DEFAULT_CONFIG_FILE_ACCESS;
  // Local config edits are optimistic: a concurrent writer between this read and
  // the final rename can still produce a lost update until a later CAS/lock layer exists.
  const current = readSourceConfigFileResult({
    configFilePath: options.configFilePath,
    readFile: access.readFile
  });

  if (!current.ok) {
    return current;
  }

  const next = options.edit(current.value);
  if (!next.ok) {
    return next;
  }

  const writeOptions: WriteSourceConfigFileOptions = {
    configFilePath: options.configFilePath,
    sourceConfig: next.value,
    authorizeWrite: options.authorizeWrite,
    access
  };

  if (options.audit !== undefined) {
    writeOptions.audit = options.audit;
  }

  if (options.reason !== undefined) {
    writeOptions.reason = options.reason;
  }

  if (options.tempFilePath !== undefined) {
    writeOptions.tempFilePath = options.tempFilePath;
  }

  return writeSourceConfigFileResult(writeOptions);
}

function readSourceConfigFile(path: string, readFile: (path: string) => string): Result<SourceConfig> {
  let rawConfig: string;

  try {
    rawConfig = readFile(path);
  } catch (error) {
    return configInvalid("Config file could not be read", {
      path,
      errorName: error instanceof Error ? error.name : "UnknownError"
    });
  }

  let parsedJson: unknown;

  try {
    parsedJson = JSON.parse(rawConfig);
  } catch {
    return configInvalid("Config file contains malformed JSON", {
      path
    });
  }

  return parseSourceConfig(parsedJson);
}

function normalizeEnvConfigFilePath(path: string | undefined): string | undefined {
  if (path === undefined || path.trim().length === 0) {
    return undefined;
  }

  return path;
}

function normalizeExplicitConfigFilePath(path: string | undefined): Result<string | undefined> {
  if (path === undefined) {
    return ok(undefined);
  }

  if (!isNonEmptyString(path)) {
    return configInvalid("configFilePath must be a non-empty string", {
      field: "configFilePath"
    });
  }

  return ok(path);
}

function normalizeLoadConfigOptions(options?: LoadConfigOptions): Result<NormalizedLoadConfigOptions> {
  const env = options?.env ?? process.env;
  const explicitConfigFilePath = normalizeExplicitConfigFilePath(options?.configFilePath);
  if (!explicitConfigFilePath.ok) {
    return explicitConfigFilePath;
  }

  return ok({
    env,
    configFilePath: explicitConfigFilePath.value ?? normalizeEnvConfigFilePath(env.DOMINIC_NEXUS_CONFIG_PATH),
    readFile: options?.readFile ?? ((path) => readFileSync(path, "utf8"))
  });
}

export function loadConfigResult(options?: LoadConfigOptions): Result<RuntimeConfig> {
  const normalizedOptions = normalizeLoadConfigOptions(options);
  if (!normalizedOptions.ok) {
    return normalizedOptions;
  }

  const normalized = normalizedOptions.value;
  let source: SourceConfig = {};

  if (normalized.configFilePath !== undefined) {
    const fileConfig = readSourceConfigFile(normalized.configFilePath, normalized.readFile);
    if (!fileConfig.ok) {
      return fileConfig;
    }

    source = fileConfig.value;
  }

  const sourceWithOverrides = applyEnvironmentOverrides(source, normalized.env);
  if (!sourceWithOverrides.ok) {
    return sourceWithOverrides;
  }

  return ok(applyRuntimeDefaults(sourceWithOverrides.value, normalized.configFilePath));
}

export function loadConfig(options?: LoadConfigOptions): RuntimeConfig {
  const result = loadConfigResult(options);

  if (!result.ok) {
    throw result.error;
  }

  return result.value;
}
