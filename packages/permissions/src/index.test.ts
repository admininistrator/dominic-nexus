import { describe, expect, it } from "vitest";
import { AllowAllDevelopmentPolicy, DefaultDenyPolicy } from "./index.js";

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
      reason: "Denied by default policy: shell.execute"
    });
  });
});

describe("AllowAllDevelopmentPolicy", () => {
  it("allows permission requests", () => {
    const policy = new AllowAllDevelopmentPolicy();

    const decision = policy.decide();

    expect(decision).toEqual({
      allowed: true,
      reason: "Allowed by development policy"
    });
  });
});
