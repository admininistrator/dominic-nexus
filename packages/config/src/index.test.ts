import { describe, expect, it } from "vitest";
import { InMemoryAuditSink } from "@dominic-nexus/audit";
import { AppError, FixedClock, REDACTED_PLACEHOLDER, SequentialIdGenerator, serializeAppError } from "@dominic-nexus/shared";
import {
  applyEnvironmentOverrides,
  applyRuntimeDefaults,
  CONFIG_ENVIRONMENT_OVERRIDES,
  editSourceConfigFileResult,
  getSourceConfigValue,
  loadConfig,
  loadConfigResult,
  mergeSourceConfig,
  parseLogLevel,
  parseSourceConfig,
  replaceSourceConfig,
  setSourceConfigValue,
  unsetSourceConfigValue,
  writeSourceConfigFileResult,
  type ConfigFileAccess,
  type ConfigWriteAuthorizationRequest
} from "./index.js";

describe("parseLogLevel", () => {
  it("defaults to info when no log level is configured", () => {
    expect(parseLogLevel(undefined)).toEqual({
      ok: true,
      value: "info"
    });
  });

  it.each(["debug", "info", "warn", "error"] as const)("accepts %s", (logLevel) => {
    expect(parseLogLevel(logLevel)).toEqual({
      ok: true,
      value: logLevel
    });
  });

  it("returns a config error for invalid log levels", () => {
    const result = parseLogLevel("verbose");

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(serializeAppError(result.error)).toEqual({
        name: "AppError",
        code: "config.invalid",
        message: "Invalid DOMINIC_NEXUS_LOG_LEVEL",
        context: {
          variable: "DOMINIC_NEXUS_LOG_LEVEL",
          allowedValues: ["debug", "info", "warn", "error"]
        }
      });
    }
  });
});

describe("loadConfigResult", () => {
  it("uses pure runtime defaults when no source config is supplied", () => {
    expect(applyRuntimeDefaults({})).toEqual({
      appName: "Dominic Nexus",
      environment: "development",
      logLevel: "info",
      stateDirectory: ".dominic-nexus/state"
    });
  });

  it("loads config from a supplied environment object", () => {
    expect(
      loadConfigResult({
        env: {
          DOMINIC_NEXUS_APP_NAME: "Test App",
          DOMINIC_NEXUS_LOG_LEVEL: "debug",
          DOMINIC_NEXUS_STATE_DIRECTORY: ".test-state",
          NODE_ENV: "test"
        }
      })
    ).toEqual({
      ok: true,
      value: {
        appName: "Test App",
        environment: "test",
        logLevel: "debug",
        stateDirectory: ".test-state"
      }
    });
  });

  it("loads and validates config from an explicit config file path", () => {
    expect(
      loadConfigResult({
        configFilePath: "test-config.json",
        env: {},
        readFile: (path) => {
          expect(path).toBe("test-config.json");
          return JSON.stringify({
            appName: "File App",
            environment: "test",
            logLevel: "warn",
            stateDirectory: ".file-state"
          });
        }
      })
    ).toEqual({
      ok: true,
      value: {
        appName: "File App",
        environment: "test",
        logLevel: "warn",
        stateDirectory: ".file-state",
        configFilePath: "test-config.json"
      }
    });
  });

  it("applies narrow environment overrides over file config", () => {
    expect(CONFIG_ENVIRONMENT_OVERRIDES).toEqual([
      "DOMINIC_NEXUS_CONFIG_PATH",
      "DOMINIC_NEXUS_APP_NAME",
      "DOMINIC_NEXUS_STATE_DIRECTORY",
      "DOMINIC_NEXUS_LOG_LEVEL",
      "NODE_ENV"
    ]);

    expect(
      loadConfigResult({
        configFilePath: "test-config.json",
        env: {
          DOMINIC_NEXUS_APP_NAME: "Env App",
          DOMINIC_NEXUS_LOG_LEVEL: "debug",
          DOMINIC_NEXUS_STATE_DIRECTORY: ".env-state",
          NODE_ENV: "override-test"
        },
        readFile: () =>
          JSON.stringify({
            appName: "File App",
            environment: "file-test",
            logLevel: "warn",
            stateDirectory: ".file-state"
          })
      })
    ).toEqual({
      ok: true,
      value: {
        appName: "Env App",
        environment: "override-test",
        logLevel: "debug",
        stateDirectory: ".env-state",
        configFilePath: "test-config.json"
      }
    });
  });

  it("fails closed when the explicit config file is missing", () => {
    const result = loadConfigResult({
      configFilePath: "missing.json",
      env: {},
      readFile: () => {
        throw new Error("ENOENT");
      }
    });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(serializeAppError(result.error)).toEqual({
        name: "AppError",
        code: "config.invalid",
        message: "Config file could not be read",
        context: {
          path: "missing.json",
          errorName: "Error"
        }
      });
    }
  });

  it("fails closed when config JSON is malformed", () => {
    const result = loadConfigResult({
      configFilePath: "bad.json",
      env: {},
      readFile: () => "{not-json"
    });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(serializeAppError(result.error)).toEqual({
        name: "AppError",
        code: "config.invalid",
        message: "Config file contains malformed JSON",
        context: {
          path: "bad.json"
        }
      });
    }
  });

  it("fails closed when config file JSON contains unknown keys", () => {
    const result = loadConfigResult({
      configFilePath: "unknown-key.json",
      env: {},
      readFile: () =>
        JSON.stringify({
          appName: "File App",
          telemetry: true
        })
    });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(serializeAppError(result.error)).toEqual({
        name: "AppError",
        code: "config.invalid",
        message: "Config source contains unknown keys",
        context: {
          unknownKeys: ["telemetry"]
        }
      });
    }
  });

  it("treats empty environment config paths as unset", () => {
    let readAttempts = 0;

    expect(
      loadConfigResult({
        env: {
          DOMINIC_NEXUS_CONFIG_PATH: "   "
        },
        readFile: () => {
          readAttempts += 1;
          throw new Error("readFile should not be called");
        }
      })
    ).toEqual({
      ok: true,
      value: {
        appName: "Dominic Nexus",
        environment: "development",
        logLevel: "info",
        stateDirectory: ".dominic-nexus/state"
      }
    });
    expect(readAttempts).toBe(0);
  });

  it("fails closed when an explicit config file path is empty", () => {
    const result = loadConfigResult({
      configFilePath: " ",
      env: {},
      readFile: () => {
        throw new Error("readFile should not be called");
      }
    });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(serializeAppError(result.error)).toEqual({
        name: "AppError",
        code: "config.invalid",
        message: "configFilePath must be a non-empty string",
        context: {
          field: "configFilePath"
        }
      });
    }
  });

  it("does not confuse environment collision keys with load options", () => {
    expect(
      loadConfigResult({
        env: {
          env: "collision",
          readFile: "collision",
          configFilePath: "collision",
          DOMINIC_NEXUS_APP_NAME: "Env App",
          DOMINIC_NEXUS_LOG_LEVEL: "error",
          NODE_ENV: "test"
        }
      })
    ).toEqual({
      ok: true,
      value: {
        appName: "Env App",
        environment: "test",
        logLevel: "error",
        stateDirectory: ".dominic-nexus/state"
      }
    });
  });

  it("throws AppError through loadConfig for invalid config", () => {
    expect(() =>
      loadConfig({
        configFilePath: "missing.json",
        env: {},
        readFile: () => {
          throw new Error("ENOENT");
        }
      })
    ).toThrow(AppError);
  });
});

describe("parseSourceConfig", () => {
  it("accepts an empty source config", () => {
    expect(parseSourceConfig({})).toEqual({
      ok: true,
      value: {}
    });
  });

  it("accepts valid source config", () => {
    expect(
      parseSourceConfig({
        appName: "Strict App",
        environment: "test",
        logLevel: "error",
        stateDirectory: ".strict-state"
      })
    ).toEqual({
      ok: true,
      value: {
        appName: "Strict App",
        environment: "test",
        logLevel: "error",
        stateDirectory: ".strict-state"
      }
    });
  });

  it.each([null, [], "string", 42])("rejects non-object source config %#", (value) => {
    const result = parseSourceConfig(value);

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(serializeAppError(result.error)).toEqual({
        name: "AppError",
        code: "config.invalid",
        message: "Config source must be a JSON object"
      });
    }
  });

  it("rejects unknown source config keys", () => {
    const result = parseSourceConfig({
      appName: "Strict App",
      telemetry: true
    });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(serializeAppError(result.error)).toEqual({
        name: "AppError",
        code: "config.invalid",
        message: "Config source contains unknown keys",
        context: {
          unknownKeys: ["telemetry"]
        }
      });
    }
  });

  it("rejects malformed values", () => {
    const result = parseSourceConfig({
      appName: "Strict App",
      environment: "",
      logLevel: "info"
    });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(serializeAppError(result.error)).toEqual({
        name: "AppError",
        code: "config.invalid",
        message: "environment must be a non-empty string",
        context: {
          field: "environment"
        }
      });
    }
  });

  it("rejects empty logLevel values", () => {
    const result = parseSourceConfig({
      logLevel: ""
    });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(serializeAppError(result.error)).toEqual({
        name: "AppError",
        code: "config.invalid",
        message: "logLevel must be one of the allowed values",
        context: {
          field: "logLevel",
          allowedValues: ["debug", "info", "warn", "error"]
        }
      });
    }
  });

  it("rejects whitespace-only appName values", () => {
    const result = parseSourceConfig({
      appName: "  "
    });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(serializeAppError(result.error)).toEqual({
        name: "AppError",
        code: "config.invalid",
        message: "appName must be a non-empty string",
        context: {
          field: "appName"
        }
      });
    }
  });

  it("rejects malformed stateDirectory values", () => {
    const empty = parseSourceConfig({
      stateDirectory: " "
    });

    expect(empty.ok).toBe(false);
    if (!empty.ok) {
      expect(serializeAppError(empty.error)).toEqual({
        name: "AppError",
        code: "config.invalid",
        message: "stateDirectory must be a non-empty string",
        context: {
          field: "stateDirectory"
        }
      });
    }

    const nul = parseSourceConfig({
      stateDirectory: "state\0dir"
    });

    expect(nul.ok).toBe(false);
    if (!nul.ok) {
      expect(serializeAppError(nul.error)).toEqual({
        name: "AppError",
        code: "config.invalid",
        message: "stateDirectory must not contain NUL bytes",
        context: {
          field: "stateDirectory"
        }
      });
    }
  });

  it("accepts env-backed SecretRef metadata without resolving secret values", () => {
    expect(
      parseSourceConfig({
        secrets: {
          openaiApiKey: {
            provider: "env",
            key: "OPENAI_API_KEY"
          }
        }
      })
    ).toEqual({
      ok: true,
      value: {
        secrets: {
          openaiApiKey: {
            provider: "env",
            key: "OPENAI_API_KEY"
          }
        }
      }
    });
  });

  it("rejects malformed SecretRef metadata", () => {
    const result = parseSourceConfig({
      secrets: {
        openaiApiKey: {
          provider: "env",
          key: ""
        }
      }
    });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(serializeAppError(result.error)).toEqual({
        name: "AppError",
        code: "config.invalid",
        message: "SecretRef key must be a non-empty string",
        context: {
          field: "secrets.openaiApiKey.key"
        }
      });
    }
  });
});

describe("source config edit primitives", () => {
  it("gets, sets, unsets, merges, and replaces strict source config values", () => {
    const source = {
      appName: "File App",
      environment: "test",
      logLevel: "warn" as const
    };

    expect(getSourceConfigValue(source, "appName")).toEqual({
      ok: true,
      value: "File App"
    });
    expect(setSourceConfigValue(source, "logLevel", "error")).toEqual({
      ok: true,
      value: {
        appName: "File App",
        environment: "test",
        logLevel: "error"
      }
    });
    expect(unsetSourceConfigValue(source, "environment")).toEqual({
      ok: true,
      value: {
        appName: "File App",
        logLevel: "warn"
      }
    });
    expect(mergeSourceConfig(source, { appName: "Merged App" })).toEqual({
      ok: true,
      value: {
        appName: "Merged App",
        environment: "test",
        logLevel: "warn"
      }
    });
    expect(replaceSourceConfig({ logLevel: "debug" })).toEqual({
      ok: true,
      value: {
        logLevel: "debug"
      }
    });
  });

  it("rejects unknown keys and redacted placeholders before writes can use them", () => {
    const unknown = setSourceConfigValue({}, "telemetry", true);
    expect(unknown.ok).toBe(false);
    if (!unknown.ok) {
      expect(serializeAppError(unknown.error)).toEqual({
        name: "AppError",
        code: "config.invalid",
        message: "Config key is unknown",
        context: {
          field: "telemetry"
        }
      });
    }

    const redacted = mergeSourceConfig(
      {
        appName: "File App"
      },
      {
        secrets: {
          openaiApiKey: {
            provider: "env",
            key: REDACTED_PLACEHOLDER
          }
        }
      }
    );

    expect(redacted.ok).toBe(false);
    if (!redacted.ok) {
      expect(serializeAppError(redacted.error)).toEqual({
        name: "AppError",
        code: "config.invalid",
        message: "Config values must not contain redacted placeholders",
        context: {
          placeholder: REDACTED_PLACEHOLDER
        }
      });
    }
  });

  it("rejects redacted placeholders nested inside arrays and objects", () => {
    const result = replaceSourceConfig({
      secrets: {
        openaiApiKey: {
          provider: "env",
          key: "OPENAI_API_KEY"
        }
      },
      nested: {
        values: ["safe", { token: REDACTED_PLACEHOLDER }]
      }
    });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(serializeAppError(result.error)).toEqual({
        name: "AppError",
        code: "config.invalid",
        message: "Config values must not contain redacted placeholders",
        context: {
          placeholder: REDACTED_PLACEHOLDER
        }
      });
    }
  });

  it("preserves SecretRef values while editing unrelated config keys", () => {
    expect(
      setSourceConfigValue(
        {
          appName: "File App",
          secrets: {
            openaiApiKey: {
              provider: "env",
              key: "OPENAI_API_KEY"
            }
          }
        },
        "appName",
        "Edited App"
      )
    ).toEqual({
      ok: true,
      value: {
        appName: "Edited App",
        secrets: {
          openaiApiKey: {
            provider: "env",
            key: "OPENAI_API_KEY"
          }
        }
      }
    });
  });
});

function createRecordingConfigFileAccess(initialFiles: Record<string, string> = {}) {
  const files = new Map(Object.entries(initialFiles));
  const operations: string[] = [];
  const access: ConfigFileAccess = {
    mkdir(dirPath) {
      operations.push(`mkdir:${dirPath}`);
    },
    readFile(filePath) {
      operations.push(`read:${filePath}`);
      const content = files.get(filePath);
      if (content === undefined) {
        throw new Error("ENOENT");
      }

      return content;
    },
    rename(fromPath, toPath) {
      operations.push(`rename:${fromPath}->${toPath}`);
      const content = files.get(fromPath);
      if (content === undefined) {
        throw new Error("ENOENT");
      }

      files.set(toPath, content);
      files.delete(fromPath);
    },
    unlink(filePath) {
      operations.push(`unlink:${filePath}`);
      files.delete(filePath);
    },
    writeFile(filePath, content) {
      operations.push(`write:${filePath}`);
      files.set(filePath, content);
    }
  };

  return {
    access,
    files,
    operations
  };
}

describe("writeSourceConfigFileResult", () => {
  it("requires write authorization before mutating the config file", async () => {
    const { access, operations } = createRecordingConfigFileAccess();
    const authorizationRequests: ConfigWriteAuthorizationRequest[] = [];

    const result = await writeSourceConfigFileResult({
      configFilePath: "C:\\workspace\\nexus.config.json",
      sourceConfig: {
        appName: "Denied App"
      },
      access,
      tempFilePath: "C:\\workspace\\.nexus.config.json.tmp",
      authorizeWrite(request) {
        authorizationRequests.push(request);
        expect(operations).toEqual([]);
        return {
          ok: false,
          error: new AppError({
            code: "filesystem.permission_denied",
            message: "Filesystem write permission denied",
            context: {
              action: "filesystem.write",
              operation: "write",
              path: request.path
            }
          })
        };
      }
    });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(serializeAppError(result.error)).toEqual({
        name: "AppError",
        code: "filesystem.permission_denied",
        message: "Filesystem write permission denied",
        context: {
          action: "filesystem.write",
          operation: "write",
          path: "C:\\workspace\\nexus.config.json"
        }
      });
    }
    expect(authorizationRequests).toEqual([
      {
        path: "C:\\workspace\\nexus.config.json",
        reason: "Write Dominic Nexus config",
        metadata: {
          operation: "replace",
          fields: ["appName"]
        }
      }
    ]);
    expect(operations).toEqual([]);
  });

  it("writes through a same-directory temp file and rename after authorization", async () => {
    const { access, files, operations } = createRecordingConfigFileAccess();

    const result = await writeSourceConfigFileResult({
      configFilePath: "C:\\workspace\\nexus.config.json",
      sourceConfig: {
        appName: "Written App",
        logLevel: "debug"
      },
      access,
      tempFilePath: "C:\\workspace\\.nexus.config.json.tmp",
      authorizeWrite() {
        return {
          ok: true,
          value: {}
        };
      }
    });

    expect(result).toEqual({
      ok: true,
      value: {
        appName: "Written App",
        logLevel: "debug"
      }
    });
    expect(files.get("C:\\workspace\\nexus.config.json")).toBe(
      JSON.stringify(
        {
          appName: "Written App",
          logLevel: "debug"
        },
        null,
        2
      ) + "\n"
    );
    expect(operations).toEqual([
      "mkdir:C:\\workspace",
      "write:C:\\workspace\\.nexus.config.json.tmp",
      "rename:C:\\workspace\\.nexus.config.json.tmp->C:\\workspace\\nexus.config.json"
    ]);
  });

  it("does not authorize or write redacted placeholders", async () => {
    const { access, operations } = createRecordingConfigFileAccess();
    const authorizationRequests: ConfigWriteAuthorizationRequest[] = [];

    const result = await writeSourceConfigFileResult({
      configFilePath: "C:\\workspace\\nexus.config.json",
      sourceConfig: {
        secrets: {
          openaiApiKey: {
            provider: "env",
            key: REDACTED_PLACEHOLDER
          }
        }
      },
      access,
      authorizeWrite(request) {
        authorizationRequests.push(request);
        return {
          ok: true,
          value: {}
        };
      }
    });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe("config.invalid");
    }
    expect(authorizationRequests).toEqual([]);
    expect(operations).toEqual([]);
  });

  it("returns a read error and does not authorize writes when edit source config is missing", async () => {
    const { access, operations } = createRecordingConfigFileAccess();
    const authorizationRequests: ConfigWriteAuthorizationRequest[] = [];

    const result = await editSourceConfigFileResult({
      configFilePath: "C:\\workspace\\missing.config.json",
      access,
      authorizeWrite(request) {
        authorizationRequests.push(request);
        return {
          ok: true,
          value: {}
        };
      },
      edit(source) {
        return setSourceConfigValue(source, "appName", "Edited App");
      }
    });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(serializeAppError(result.error)).toEqual({
        name: "AppError",
        code: "config.invalid",
        message: "Config file could not be read",
        context: {
          path: "C:\\workspace\\missing.config.json",
          errorName: "Error"
        }
      });
    }
    expect(authorizationRequests).toEqual([]);
    expect(operations).toEqual(["read:C:\\workspace\\missing.config.json"]);
  });

  it("does not authorize or write when an edit callback returns an invalid config result", async () => {
    const { access, operations } = createRecordingConfigFileAccess({
      "C:\\workspace\\nexus.config.json": JSON.stringify({
        appName: "File App"
      })
    });
    const authorizationRequests: ConfigWriteAuthorizationRequest[] = [];

    const result = await editSourceConfigFileResult({
      configFilePath: "C:\\workspace\\nexus.config.json",
      access,
      authorizeWrite(request) {
        authorizationRequests.push(request);
        return {
          ok: true,
          value: {}
        };
      },
      edit(source) {
        return setSourceConfigValue(source, "telemetry", true);
      }
    });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(serializeAppError(result.error)).toEqual({
        name: "AppError",
        code: "config.invalid",
        message: "Config key is unknown",
        context: {
          field: "telemetry"
        }
      });
    }
    expect(authorizationRequests).toEqual([]);
    expect(operations).toEqual(["read:C:\\workspace\\nexus.config.json"]);
  });

  it("edits existing config, preserves SecretRefs, and audits without config values", async () => {
    const audit = new InMemoryAuditSink();
    const { access, files } = createRecordingConfigFileAccess({
      "C:\\workspace\\nexus.config.json": JSON.stringify({
        appName: "File App",
        secrets: {
          openaiApiKey: {
            provider: "env",
            key: "OPENAI_API_KEY"
          }
        }
      })
    });

    const result = await editSourceConfigFileResult({
      configFilePath: "C:\\workspace\\nexus.config.json",
      access,
      tempFilePath: "C:\\workspace\\.nexus.config.json.tmp",
      audit: {
        audit,
        clock: new FixedClock("2026-05-09T00:00:00.000Z"),
        idGenerator: new SequentialIdGenerator({ eventPrefix: "config-audit" })
      },
      authorizeWrite() {
        return {
          ok: true,
          value: {}
        };
      },
      edit(source) {
        return setSourceConfigValue(source, "appName", "Edited App");
      }
    });

    expect(result.ok).toBe(true);
    expect(files.get("C:\\workspace\\nexus.config.json")).toBe(
      JSON.stringify(
        {
          appName: "Edited App",
          secrets: {
            openaiApiKey: {
              provider: "env",
              key: "OPENAI_API_KEY"
            }
          }
        },
        null,
        2
      ) + "\n"
    );

    expect(audit.listEvents()).toEqual([
      expect.objectContaining({
        eventId: "config-audit-1",
        action: "config.write",
        decision: "allowed",
        outcome: "succeeded",
        metadata: {
          operation: "replace",
          fields: ["appName", "secrets"]
        }
      })
    ]);
    expect(JSON.stringify(audit.listEvents())).not.toContain("OPENAI_API_KEY");
  });
});

describe("applyEnvironmentOverrides", () => {
  it("returns source unchanged when no relevant environment overrides are set", () => {
    expect(
      applyEnvironmentOverrides(
        {
          appName: "File App",
          environment: "file-test",
          logLevel: "warn",
          stateDirectory: ".file-state"
        },
        {
          IRRELEVANT: "ignored"
        }
      )
    ).toEqual({
      ok: true,
      value: {
        appName: "File App",
        environment: "file-test",
        logLevel: "warn",
        stateDirectory: ".file-state"
      }
    });
  });

  it("revalidates source config before applying overrides", () => {
    const result = applyEnvironmentOverrides(
      {
        appName: "File App",
        telemetry: true
      } as unknown as Parameters<typeof applyEnvironmentOverrides>[0],
      {
        DOMINIC_NEXUS_LOG_LEVEL: "debug"
      }
    );

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(serializeAppError(result.error)).toEqual({
        name: "AppError",
        code: "config.invalid",
        message: "Config source contains unknown keys",
        context: {
          unknownKeys: ["telemetry"]
        }
      });
    }
  });

  it("applies environment overrides after source validation", () => {
    expect(
      applyEnvironmentOverrides(
        {
          appName: "File App",
          environment: "file-test",
          logLevel: "warn"
        },
        {
          DOMINIC_NEXUS_APP_NAME: "Env App",
          DOMINIC_NEXUS_STATE_DIRECTORY: ".env-state",
          DOMINIC_NEXUS_LOG_LEVEL: "debug",
          NODE_ENV: "env-test"
        }
      )
    ).toEqual({
      ok: true,
      value: {
        appName: "Env App",
        environment: "env-test",
        logLevel: "debug",
        stateDirectory: ".env-state"
      }
    });
  });

  it("rejects malformed environment override values", () => {
    const result = applyEnvironmentOverrides(
      {
        appName: "File App"
      },
      {
        DOMINIC_NEXUS_LOG_LEVEL: "verbose"
      }
    );

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(serializeAppError(result.error)).toEqual({
        name: "AppError",
        code: "config.invalid",
        message: "logLevel must be one of the allowed values",
        context: {
          field: "logLevel",
          allowedValues: ["debug", "info", "warn", "error"]
        }
      });
    }
  });
});
