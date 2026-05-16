import { describe, expect, it } from "vitest";
import { InMemoryAuditSink } from "@dominic-nexus/audit";
import { FixedClock, REDACTED_PLACEHOLDER, SequentialIdGenerator, serializeAppError } from "@dominic-nexus/shared";
import {
  allowPermissionDecision,
  AllowAllDevelopmentPolicy,
  approvalRequiredPermissionDecision,
  createNetworkRequestApproval,
  createNetworkRequestPermissionRequest,
  createShellExecutionApproval,
  createShellExecutionPermissionRequest,
  decidePermissionWithAudit,
  DefaultDenyPolicy,
  InteractiveApprovalPolicy,
  isNetworkRequestApprovalBoundToRequest,
  isRiskyShellEnvKey,
  isShellExecutionApprovalBoundToRequest,
  NetworkPolicy,
  permissionDeniedError,
  serializePermissionDecision,
  ShellPolicy,
  validateNetworkRequest,
  validateShellExecutionRequest,
  type PermissionDecision,
  type PermissionRequest,
  type PolicyEngine
} from "./index.js";

class RecordingPolicy implements PolicyEngine {
  readonly requests: PermissionRequest[] = [];

  constructor(private readonly decision: PermissionDecision = { allowed: true }) {}

  decide(request: PermissionRequest): PermissionDecision {
    this.requests.push(request);
    return this.decision;
  }
}

describe("DefaultDenyPolicy", () => {
  it("denies permission requests by default", () => {
    const policy = new DefaultDenyPolicy();

    const decision = policy.decide({
      action: "shell.execute",
      reason: "test shell access",
      resource: "echo"
    });

    expect(decision).toEqual({
      allowed: false,
      kind: "deny",
      policySource: "default-deny",
      reason: "Denied by default policy: shell.execute"
    });
  });

  it("denies network.request by default", () => {
    const policy = new DefaultDenyPolicy();

    const decision = policy.decide({
      action: "network.request",
      reason: "test network access",
      resource: "https://example.com/"
    });

    expect(decision).toEqual({
      allowed: false,
      kind: "deny",
      policySource: "default-deny",
      reason: "Denied by default policy: network.request"
    });
  });
});

describe("shell execution request validation", () => {
  it("rejects missing or empty commands", () => {
    expect(validateShellExecutionRequest({}).ok).toBe(false);
    expect(validateShellExecutionRequest({ command: "" }).ok).toBe(false);
    expect(validateShellExecutionRequest({ command: "   " }).ok).toBe(false);
  });

  it("rejects commands containing NUL bytes", () => {
    expect(validateShellExecutionRequest({ command: "echo\0ok" }).ok).toBe(false);
    expect(validateShellExecutionRequest({ command: "\0" }).ok).toBe(false);
  });

  it("requires cwd to be a non-empty string when provided", () => {
    expect(validateShellExecutionRequest({ command: "echo ok", cwd: "" }).ok).toBe(false);
    expect(validateShellExecutionRequest({ command: "echo ok", cwd: 42 }).ok).toBe(false);

    const result = validateShellExecutionRequest({ command: "echo ok", cwd: "C:\\workspace" });

    expect(result).toEqual({
      ok: true,
      value: {
        command: "echo ok",
        cwd: "C:\\workspace",
        env: {}
      }
    });
  });

  it("rejects cwd values containing NUL bytes", () => {
    expect(validateShellExecutionRequest({ command: "echo ok", cwd: "C:\\workspace\0evil" }).ok).toBe(false);
  });

  it("requires env to be an object with string values", () => {
    expect(validateShellExecutionRequest({ command: "echo ok", env: "KEY=value" }).ok).toBe(false);
    expect(validateShellExecutionRequest({ command: "echo ok", env: ["KEY=value"] }).ok).toBe(false);
    expect(validateShellExecutionRequest({ command: "echo ok", env: { SAFE: 1 } }).ok).toBe(false);
  });

  it("rejects env keys and values containing NUL bytes", () => {
    expect(validateShellExecutionRequest({ command: "echo ok", env: { "SAFE\0KEY": "value" } }).ok).toBe(false);
    expect(validateShellExecutionRequest({ command: "echo ok", env: { SAFE_KEY: "value\0truncated" } }).ok).toBe(false);
  });

  it.each(["PATH", "Path", "LD_PRELOAD", "LD_LIBRARY_PATH", "LD_CUSTOM", "DYLD_INSERT_LIBRARIES", "DYLD_LIBRARY_PATH", "DYLD_CUSTOM"])(
    "rejects risky env override %s",
    (key) => {
      expect(isRiskyShellEnvKey(key)).toBe(true);
      expect(validateShellExecutionRequest({ command: "echo ok", env: { [key]: "value" } }).ok).toBe(false);
    }
  );

  it("accepts valid safe env overrides", () => {
    const result = validateShellExecutionRequest({
      command: "pnpm.cmd test",
      env: {
        DOMINIC_NEXUS_MODE: "test",
        SAFE_FLAG: "1"
      }
    });

    expect(result).toEqual({
      ok: true,
      value: {
        command: "pnpm.cmd test",
        env: {
          DOMINIC_NEXUS_MODE: "test",
          SAFE_FLAG: "1"
        }
      }
    });
  });

  it("rejects invalid timeoutMs values and accepts positive integers", () => {
    for (const timeoutMs of [0, -1, 1.5, Number.POSITIVE_INFINITY, "1000"]) {
      expect(validateShellExecutionRequest({ command: "echo ok", timeoutMs }).ok).toBe(false);
    }

    expect(validateShellExecutionRequest({ command: "echo ok", timeoutMs: 1000 })).toEqual({
      ok: true,
      value: {
        command: "echo ok",
        env: {},
        timeoutMs: 1000
      }
    });
  });
});

describe("shell execution approval binding", () => {
  it("binds permission approvals to the exact normalized request", () => {
    const requestResult = validateShellExecutionRequest({
      command: "pnpm.cmd --filter @dominic-nexus/permissions test",
      cwd: "C:\\workspace\\dominic-nexus",
      env: {
        SAFE_B: "2",
        SAFE_A: "1"
      },
      timeoutMs: 30000
    });

    expect(requestResult.ok).toBe(true);
    if (!requestResult.ok) {
      return;
    }

    const permissionRequest = createShellExecutionPermissionRequest(requestResult.value, {
      reason: "Run package tests",
      metadata: {
        traceId: "shell-test"
      }
    });
    const approval = createShellExecutionApproval(
      requestResult.value,
      allowPermissionDecision({
        policySource: "test-policy",
        reason: "Allowed in test"
      }),
      permissionRequest
    );

    expect(permissionRequest).toEqual({
      action: "shell.execute",
      reason: "Run package tests",
      resource: "pnpm.cmd --filter @dominic-nexus/permissions test",
      metadata: {
        traceId: "shell-test",
        shellExecutionRequest: {
          command: "pnpm.cmd --filter @dominic-nexus/permissions test",
          cwd: "C:\\workspace\\dominic-nexus",
          env: {
            SAFE_A: "1",
            SAFE_B: "2"
          },
          timeoutMs: 30000
        }
      }
    });
    expect(approval.binding).toEqual(permissionRequest.metadata?.shellExecutionRequest);
    expect(isShellExecutionApprovalBoundToRequest(approval, requestResult.value)).toBe(true);
    expect(
      isShellExecutionApprovalBoundToRequest(approval, {
        ...requestResult.value,
        env: {
          SAFE_A: "1",
          SAFE_B: "changed"
        }
      })
    ).toBe(false);
  });

  it("uses shell.execute permission and remains denied under DefaultDenyPolicy", async () => {
    const shellPolicy = new ShellPolicy(new DefaultDenyPolicy());
    const result = await shellPolicy.authorize({
      command: "echo ok"
    });

    expect(result).toEqual({
      ok: false,
      error: expect.objectContaining({
        code: "permission.denied",
        message: "Shell execution permission denied"
      })
    });
  });

  it("audits shell permission metadata without env values", async () => {
    const audit = new InMemoryAuditSink();
    const shellPolicy = new ShellPolicy(new RecordingPolicy());

    const result = await shellPolicy.authorize(
      {
        command: "echo safe-command",
        cwd: "C:\\workspace",
        env: {
          SAFE_ENV: "raw-env-secret"
        },
        timeoutMs: 1000
      },
      {
        audit: {
          audit,
          clock: new FixedClock("2026-05-08T00:00:00.000Z"),
          idGenerator: new SequentialIdGenerator({ eventPrefix: "shell-audit" })
        }
      }
    );

    expect(result.ok).toBe(true);
    expect(audit.listEvents()).toEqual([
      expect.objectContaining({
        eventId: "shell-audit-1",
        action: "permission.decide",
        decision: "allowed",
        outcome: "succeeded",
        metadata: expect.objectContaining({
          resource: "echo safe-command",
          requestMetadata: {
            shellExecutionRequest: {
              command: "echo safe-command",
              cwd: "C:\\workspace",
              env: {
                SAFE_ENV: REDACTED_PLACEHOLDER
              },
              envKeys: ["SAFE_ENV"],
              timeoutMs: 1000
            }
          }
        })
      })
    ]);
    expect(JSON.stringify(audit.listEvents())).not.toContain("raw-env-secret");
  });
});

describe("network request validation", () => {
  it("rejects missing or empty url, resource, and host metadata", () => {
    expect(validateNetworkRequest({}).ok).toBe(false);
    expect(validateNetworkRequest({ url: "" }).ok).toBe(false);
    expect(validateNetworkRequest({ resource: "   " }).ok).toBe(false);
    expect(validateNetworkRequest({ host: "" }).ok).toBe(false);
  });

  it("rejects invalid URLs", () => {
    expect(validateNetworkRequest({ url: "not a url" }).ok).toBe(false);
  });

  it.each(["file:///C:/secret.txt", "data:text/plain,hello", "javascript:alert(1)"])(
    "rejects non-network URL protocol %s",
    (url) => {
      expect(validateNetworkRequest({ url }).ok).toBe(false);
    }
  );

  it("accepts valid https URLs and normalizes host and protocol", () => {
    expect(validateNetworkRequest({ url: "https://example.com/path" })).toEqual({
      ok: true,
      value: {
        url: "https://example.com/path",
        host: "example.com",
        protocol: "https:",
        headers: {}
      }
    });
  });

  it.each([
    ["ws://echo.example.com/ws", "echo.example.com", "ws:"],
    ["wss://secure.example.com/ws", "secure.example.com", "wss:"]
  ])("accepts WebSocket URL protocol %s", (url, host, protocol) => {
    expect(validateNetworkRequest({ url })).toEqual({
      ok: true,
      value: {
        url,
        host,
        protocol,
        headers: {}
      }
    });
  });

  it("accepts resource-only metadata with a valid protocol", () => {
    expect(validateNetworkRequest({ resource: "my-api", protocol: "https:" })).toEqual({
      ok: true,
      value: {
        resource: "my-api",
        protocol: "https:",
        headers: {}
      }
    });
  });

  it("accepts safe methods and normalizes them to uppercase", () => {
    expect(validateNetworkRequest({ host: "example.com", method: "post" })).toEqual({
      ok: true,
      value: {
        host: "example.com",
        method: "POST",
        headers: {}
      }
    });
  });

  it("rejects methods containing whitespace or NUL bytes", () => {
    expect(validateNetworkRequest({ host: "example.com", method: "PO ST" }).ok).toBe(false);
    expect(validateNetworkRequest({ host: "example.com", method: "POST\0" }).ok).toBe(false);
  });

  it("requires headers to be string-string metadata", () => {
    expect(validateNetworkRequest({ host: "example.com", headers: "Authorization: token" }).ok).toBe(false);
    expect(validateNetworkRequest({ host: "example.com", headers: ["Authorization: token"] }).ok).toBe(false);
    expect(validateNetworkRequest({ host: "example.com", headers: { Accept: 1 } }).ok).toBe(false);

    expect(
      validateNetworkRequest({
        host: "example.com",
        headers: {
          "X-Trace": "trace-1"
        }
      })
    ).toEqual({
      ok: true,
      value: {
        host: "example.com",
        headers: {
          "X-Trace": "trace-1"
        }
      }
    });
  });

  it("rejects explicit host or protocol metadata that conflicts with the URL", () => {
    expect(validateNetworkRequest({ url: "https://example.com/path", host: "other.example" }).ok).toBe(false);
    expect(validateNetworkRequest({ url: "https://example.com/path", protocol: "http" }).ok).toBe(false);
  });
});

describe("network request approval binding", () => {
  it("binds permission approvals to the exact normalized network request", () => {
    const requestResult = validateNetworkRequest({
      url: "https://example.com/path",
      resource: "example-api",
      method: "post",
      headers: {
        "X-Trace-B": "2",
        "X-Trace-A": "1"
      }
    });

    expect(requestResult.ok).toBe(true);
    if (!requestResult.ok) {
      return;
    }

    const permissionRequest = createNetworkRequestPermissionRequest(requestResult.value, {
      reason: "Fetch example API",
      metadata: {
        traceId: "network-test"
      }
    });
    const approval = createNetworkRequestApproval(
      requestResult.value,
      allowPermissionDecision({
        policySource: "test-policy",
        reason: "Allowed in test"
      }),
      permissionRequest
    );

    expect(permissionRequest).toEqual({
      action: "network.request",
      reason: "Fetch example API",
      resource: "example-api",
      metadata: {
        traceId: "network-test",
        networkRequest: {
          url: "https://example.com/path",
          resource: "example-api",
          host: "example.com",
          protocol: "https:",
          method: "POST",
          headers: {
            "X-Trace-A": "1",
            "X-Trace-B": "2"
          }
        }
      }
    });
    expect(approval.binding).toEqual(permissionRequest.metadata?.networkRequest);
    expect(isNetworkRequestApprovalBoundToRequest(approval, requestResult.value)).toBe(true);
    expect(
      isNetworkRequestApprovalBoundToRequest(approval, {
        ...requestResult.value,
        method: "GET"
      })
    ).toBe(false);
  });

  it("uses network.request permission, denies by default, and audits redacted metadata", async () => {
    const audit = new InMemoryAuditSink();
    const networkPolicy = new NetworkPolicy(new DefaultDenyPolicy());

    const result = await networkPolicy.authorize(
      {
        url: "https://example.com/path",
        method: "get",
        headers: {
          Authorization: "Bearer secret-token",
          Cookie: "session=secret-cookie",
          "X-Api-Key": "secret-key",
          Accept: "application/json"
        }
      },
      {
        audit: {
          audit,
          clock: new FixedClock("2026-05-08T00:00:00.000Z"),
          idGenerator: new SequentialIdGenerator({ eventPrefix: "network-audit" })
        }
      }
    );

    expect(result).toEqual({
      ok: false,
      error: expect.objectContaining({
        code: "permission.denied",
        message: "Network request permission denied"
      })
    });

    const events = audit.listEvents();
    expect(events).toEqual([
      expect.objectContaining({
        eventId: "network-audit-1",
        action: "permission.decide",
        decision: "denied",
        outcome: "denied",
        metadata: expect.objectContaining({
          allowed: false,
          decisionKind: "deny",
          policySource: "default-deny",
          resource: "https://example.com/path",
          requestMetadata: {
            networkRequest: {
              url: "https://example.com/path",
              host: "example.com",
              protocol: "https:",
              method: "GET",
              headers: {
                Accept: "application/json",
                Authorization: REDACTED_PLACEHOLDER,
                Cookie: REDACTED_PLACEHOLDER,
                "X-Api-Key": REDACTED_PLACEHOLDER
              }
            }
          }
        })
      })
    ]);
    expect(JSON.stringify(events)).not.toContain("secret-token");
    expect(JSON.stringify(events)).not.toContain("secret-cookie");
    expect(JSON.stringify(events)).not.toContain("secret-key");
  });

  it("allows valid requests and returns an exact approval binding", async () => {
    const networkPolicy = new NetworkPolicy(new AllowAllDevelopmentPolicy());
    const result = await networkPolicy.authorize({
      url: "https://example.com/path?trace=keep-in-binding#section",
      method: "get",
      headers: {
        "X-Trace": "trace-1"
      }
    });

    expect(result.ok).toBe(true);
    if (!result.ok) {
      return;
    }

    expect(result.value.decision).toEqual({
      allowed: true,
      kind: "allow",
      policySource: "allow-all-development",
      reason: "Allowed by development policy"
    });
    expect(result.value.permissionRequest.action).toBe("network.request");
    expect(result.value.permissionRequest.resource).toBe("https://example.com/path");
    expect(result.value.binding).toEqual({
      url: "https://example.com/path?trace=keep-in-binding#section",
      host: "example.com",
      protocol: "https:",
      method: "GET",
      headers: {
        "X-Trace": "trace-1"
      }
    });
    expect(isNetworkRequestApprovalBoundToRequest(result.value, result.value.binding)).toBe(true);
  });

  it("does not leak URL query, fragment, or userinfo in audit metadata", async () => {
    const audit = new InMemoryAuditSink();
    const networkPolicy = new NetworkPolicy(new DefaultDenyPolicy());

    const result = await networkPolicy.authorize(
      {
        url: "https://user:password@api.example.com/data?token=secret-token#frag",
        method: "get"
      },
      {
        audit: {
          audit,
          clock: new FixedClock("2026-05-08T00:00:00.000Z"),
          idGenerator: new SequentialIdGenerator({ eventPrefix: "network-url-audit" })
        }
      }
    );

    expect(result).toEqual({
      ok: false,
      error: expect.objectContaining({
        code: "permission.denied",
        message: "Network request permission denied",
        context: {
          action: "network.request",
          resource: "https://api.example.com/data"
        }
      })
    });

    const events = audit.listEvents();
    expect(events).toEqual([
      expect.objectContaining({
        eventId: "network-url-audit-1",
        action: "permission.decide",
        decision: "denied",
        outcome: "denied",
        metadata: expect.objectContaining({
          resource: "https://api.example.com/data",
          requestMetadata: {
            networkRequest: {
              url: "https://api.example.com/data",
              host: "api.example.com",
              protocol: "https:",
              method: "GET",
              headers: {}
            }
          }
        })
      })
    ]);
    expect(JSON.stringify(events)).not.toContain("secret-token");
    expect(JSON.stringify(events)).not.toContain("?token=");
    expect(JSON.stringify(events)).not.toContain("#frag");
    expect(JSON.stringify(events)).not.toContain("user:password");
  });
});

describe("AllowAllDevelopmentPolicy", () => {
  it("allows permission requests", () => {
    const policy = new AllowAllDevelopmentPolicy();

    const decision = policy.decide();

    expect(decision).toEqual({
      allowed: true,
      kind: "allow",
      policySource: "allow-all-development",
      reason: "Allowed by development policy"
    });
  });
});

describe("permission decision helpers", () => {
  it("serializes decisions with redacted audit metadata", () => {
    expect(
      serializePermissionDecision(
        allowPermissionDecision({
          policySource: "test-policy",
          reason: "Allowed in test",
          auditMetadata: {
            requestId: "request-1",
            token: "secret-token"
          }
        })
      )
    ).toEqual({
      allowed: true,
      kind: "allow",
      policySource: "test-policy",
      reason: "Allowed in test",
      auditMetadata: {
        requestId: "request-1",
        token: REDACTED_PLACEHOLDER
      }
    });
  });

  it("can represent an approval-required decision before a prompt is resolved", () => {
    expect(
      approvalRequiredPermissionDecision({
        policySource: "test-policy",
        reason: "Needs local operator approval"
      })
    ).toEqual({
      allowed: false,
      kind: "approval-required",
      policySource: "test-policy",
      reason: "Needs local operator approval",
      approval: {
        state: "requested",
        promptRequired: true
      }
    });
  });
});

describe("InteractiveApprovalPolicy", () => {
  it("allows a risky action when the prompt returns allow", async () => {
    const prompts: unknown[] = [];
    const policy = new InteractiveApprovalPolicy({
      prompt(request) {
        prompts.push(request);
        return "allow";
      }
    });

    await expect(
      policy.decide({
        action: "shell.execute",
        reason: "Run a local command",
        resource: "pnpm.cmd test",
        metadata: {
          ignored: "metadata is not sent to prompt"
        }
      })
    ).resolves.toEqual({
      allowed: true,
      kind: "allow",
      policySource: "interactive-approval",
      approval: {
        state: "user-approved",
        promptRequired: true,
        response: "allow"
      },
      auditMetadata: {
        risky: true
      },
      reason: "Approved by user: shell.execute"
    });
    expect(prompts).toEqual([
      {
        action: "shell.execute",
        reason: "Run a local command",
        resource: "pnpm.cmd test"
      }
    ]);
  });

  it("denies a risky action when the prompt returns deny", async () => {
    const policy = new InteractiveApprovalPolicy({
      prompt() {
        return "deny";
      }
    });

    await expect(
      policy.decide({
        action: "network.request",
        reason: "Fetch remote data",
        resource: "https://example.invalid"
      })
    ).resolves.toEqual({
      allowed: false,
      kind: "deny",
      policySource: "interactive-approval",
      approval: {
        state: "user-denied",
        promptRequired: true,
        response: "deny"
      },
      auditMetadata: {
        risky: true
      },
      reason: "Denied by user: network.request"
    });
  });

  it("defaults to deny for invalid prompt answers", async () => {
    const policy = new InteractiveApprovalPolicy({
      prompt() {
        return "maybe";
      }
    });

    await expect(
      policy.decide({
        action: "filesystem.write",
        reason: "Write a file",
        resource: "notes.txt"
      })
    ).resolves.toEqual({
      allowed: false,
      kind: "deny",
      policySource: "interactive-approval",
      approval: {
        state: "invalid-response",
        promptRequired: true,
        response: "invalid"
      },
      auditMetadata: {
        risky: true
      },
      reason: "Denied by default after invalid approval response: filesystem.write"
    });
  });

  it("asks for approval before provider.call", async () => {
    const prompts: unknown[] = [];
    const policy = new InteractiveApprovalPolicy({
      prompt(request) {
        prompts.push(request);
        return "yes";
      }
    });

    await expect(
      policy.decide({
        action: "provider.call",
        reason: "Call local mock provider",
        resource: "mock"
      })
    ).resolves.toEqual({
      allowed: true,
      kind: "allow",
      policySource: "interactive-approval",
      approval: {
        state: "user-approved",
        promptRequired: true,
        response: "allow"
      },
      auditMetadata: {
        risky: true
      },
      reason: "Approved by user: provider.call"
    });
    expect(prompts).toEqual([
      {
        action: "provider.call",
        reason: "Call local mock provider",
        resource: "mock"
      }
    ]);
  });

  it("allows non-risky actions without prompting", async () => {
    const prompts: unknown[] = [];
    const policy = new InteractiveApprovalPolicy({
      prompt(request) {
        prompts.push(request);
        return "deny";
      }
    });

    await expect(
      policy.decide({
        action: "filesystem.read",
        reason: "Read a local file",
        resource: "README.md"
      })
    ).resolves.toEqual({
      allowed: true,
      kind: "allow",
      policySource: "interactive-approval",
      approval: {
        state: "not-required",
        promptRequired: false
      },
      auditMetadata: {
        risky: false
      },
      reason: "Allowed without approval: filesystem.read"
    });
    expect(prompts).toEqual([]);
  });
});

describe("permissionDeniedError", () => {
  it("serializes permission failures without request metadata", () => {
    const error = permissionDeniedError({
      action: "secret.read",
      reason: "Read secret",
      resource: "DOMINIC_NEXUS_API_KEY",
      metadata: {
        token: "secret-token"
      }
    });

    expect(serializeAppError(error)).toEqual({
      name: "AppError",
      code: "permission.denied",
      message: "Permission denied: secret.read",
      context: {
        action: "secret.read",
        resource: REDACTED_PLACEHOLDER
      }
    });
    expect(JSON.stringify(serializeAppError(error))).not.toContain("DOMINIC_NEXUS_API_KEY");
  });
});

describe("decidePermissionWithAudit", () => {
  it("returns policy decisions when audit context is absent", async () => {
    const policy = new RecordingPolicy({ allowed: false, reason: "blocked" });

    await expect(
      decidePermissionWithAudit(policy, {
        action: "network.request",
        reason: "Fetch remote data",
        resource: "https://example.invalid"
      })
    ).resolves.toEqual({
      allowed: false,
      kind: "deny",
      policySource: "custom-policy",
      reason: "blocked"
    });
    expect(policy.requests).toEqual([
      {
        action: "network.request",
        reason: "Fetch remote data",
        resource: "https://example.invalid"
      }
    ]);
  });

  it("audits decisions when audit context is present", async () => {
    const audit = new InMemoryAuditSink();
    const policy = new RecordingPolicy();

    await expect(
      decidePermissionWithAudit(
        policy,
        {
          action: "secret.read",
          reason: "Read secret",
          resource: "DOMINIC_NEXUS_TEST_SECRET",
          metadata: {
            token: "secret-token",
            config: {
              api_key: "nested-secret-key",
              visible: "safe"
            }
          }
        },
        {
          audit,
          clock: new FixedClock("2026-05-08T00:00:00.000Z"),
          idGenerator: new SequentialIdGenerator({ eventPrefix: "permission-audit" })
        }
      )
    ).resolves.toEqual({
      allowed: true,
      kind: "allow",
      policySource: "custom-policy"
    });

    const events = audit.listEvents();
    expect(events).toEqual([
      expect.objectContaining({
        eventId: "permission-audit-1",
        action: "permission.decide",
        decision: "allowed",
        outcome: "succeeded",
        metadata: expect.objectContaining({
          allowed: true,
          decisionKind: "allow",
          policySource: "custom-policy",
          resource: REDACTED_PLACEHOLDER,
          requestMetadata: {
            token: REDACTED_PLACEHOLDER,
            config: {
              api_key: REDACTED_PLACEHOLDER,
              visible: "safe"
            }
          }
        })
      })
    ]);
    expect(JSON.stringify(events)).not.toContain("secret-token");
    expect(JSON.stringify(events)).not.toContain("nested-secret-key");
    expect(JSON.stringify(events)).not.toContain("DOMINIC_NEXUS_TEST_SECRET");
  });
});
