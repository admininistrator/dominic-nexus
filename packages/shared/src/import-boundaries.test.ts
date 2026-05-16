import { spawnSync } from "node:child_process";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
const checkerPath = path.join(repoRoot, "scripts", "check-import-boundaries.mjs");
const workspaceScope = "@dominic-nexus";

function workspacePackage(name: string): string {
  return `${workspaceScope}/${name}`;
}

async function createFixtureWorkspace(): Promise<string> {
  return mkdtemp(path.join(tmpdir(), "dominic-nexus-boundaries-"));
}

async function writeWorkspacePackage(
  root: string,
  workspacePath: string,
  packageName: string,
  source: string,
  dependencies: Record<string, string> = {}
): Promise<void> {
  const packageDir = path.join(root, workspacePath);
  await mkdir(path.join(packageDir, "src"), { recursive: true });
  await writeFile(
    path.join(packageDir, "package.json"),
    `${JSON.stringify(
      {
        name: packageName,
        version: "0.0.0",
        private: true,
        type: "module",
        dependencies
      },
      null,
      2
    )}\n`
  );
  await writeFile(path.join(packageDir, "src", "index.ts"), source);
}

function runChecker(root: string): ReturnType<typeof spawnSync> {
  return spawnSync(process.execPath, [checkerPath, "--root", root], {
    encoding: "utf8"
  });
}

async function withFixtureWorkspace<T>(callback: (root: string) => Promise<T>): Promise<T> {
  const root = await createFixtureWorkspace();

  try {
    return await callback(root);
  } finally {
    await rm(root, { force: true, recursive: true });
  }
}

describe("import boundary checker", () => {
  it("allows the current workspace package graph", async () => {
    const result = runChecker(repoRoot);

    expect(result.status).toBe(0);
    expect(result.stderr).toBe("");
  });

  it("allows documented package edges", async () => {
    await withFixtureWorkspace(async (root) => {
      await writeWorkspacePackage(
        root,
        "packages/providers",
        workspacePackage("providers"),
        [
          `import { appendAuditEvent } from "${workspacePackage("audit")}";`,
          `import type { PolicyEngine } from "${workspacePackage("permissions")}";`,
          `import type { JsonValue } from "${workspacePackage("shared")}";`,
          "export const providerContract = true;"
        ].join("\n"),
        {
          [workspacePackage("audit")]: "workspace:*",
          [workspacePackage("permissions")]: "workspace:*",
          [workspacePackage("shared")]: "workspace:*"
        }
      );
      await writeWorkspacePackage(
        root,
        "packages/core",
        workspacePackage("core"),
        [
          `import type { ProviderRegistry } from "${workspacePackage("providers")}";`,
          `import { ToolRegistry } from "${workspacePackage("tools")}";`,
          `export type { JsonValue } from "${workspacePackage("shared")}";`
        ].join("\n"),
        {
          [workspacePackage("providers")]: "workspace:*",
          [workspacePackage("shared")]: "workspace:*",
          [workspacePackage("tools")]: "workspace:*"
        }
      );
      await writeWorkspacePackage(
        root,
        "packages/plugin-sdk",
        workspacePackage("plugin-sdk"),
        `import type { JsonValue } from "${workspacePackage("shared")}";\nexport type PluginValue = JsonValue;\n`,
        {
          [workspacePackage("shared")]: "workspace:*"
        }
      );

      const result = runChecker(root);

      expect(result.status).toBe(0);
      expect(result.stderr).toBe("");
    });
  });

  it.each([
    {
      name: "providers cannot import core",
      packageName: workspacePackage("providers"),
      source: `import type { RuntimeContext } from "${workspacePackage("core")}";\nexport const value = 1;\n`,
      workspacePath: "packages/providers"
    },
    {
      name: "channels cannot export core types",
      packageName: workspacePackage("channels"),
      source: `export type { RuntimeContext } from "${workspacePackage("core")}";\n`,
      workspacePath: "packages/channels"
    },
    {
      name: "channels cannot export star from core",
      packageName: workspacePackage("channels"),
      source: `export * from "${workspacePackage("core")}";\n`,
      workspacePath: "packages/channels"
    },
    {
      name: "memory cannot import core",
      packageName: workspacePackage("memory"),
      source: `import type { RuntimeContext } from "${workspacePackage("core")}";\nexport const value = 1;\n`,
      workspacePath: "packages/memory"
    },
    {
      name: "config cannot import core",
      packageName: workspacePackage("config"),
      source: `import type { RuntimeContext } from "${workspacePackage("core")}";\nexport const value = 1;\n`,
      workspacePath: "packages/config"
    },
    {
      name: "logging cannot import core",
      packageName: workspacePackage("logging"),
      source: `import type { RuntimeContext } from "${workspacePackage("core")}";\nexport const value = 1;\n`,
      workspacePath: "packages/logging"
    },
    {
      name: "permissions cannot import core",
      packageName: workspacePackage("permissions"),
      source: `import type { RuntimeContext } from "${workspacePackage("core")}";\nexport const value = 1;\n`,
      workspacePath: "packages/permissions"
    },
    {
      name: "plugin-sdk cannot import core",
      packageName: workspacePackage("plugin-sdk"),
      source: `import { createRuntimeContext } from "${workspacePackage("core")}";\nexport const value = createRuntimeContext;\n`,
      workspacePath: "packages/plugin-sdk"
    },
    {
      name: "plugin-sdk cannot import secrets",
      packageName: workspacePackage("plugin-sdk"),
      source: `import type { SecretRef } from "${workspacePackage("secrets")}";\nexport type Value = SecretRef;\n`,
      workspacePath: "packages/plugin-sdk"
    },
    {
      name: "tools cannot dynamically import core",
      packageName: workspacePackage("tools"),
      source: `export async function loadCore() { return import("${workspacePackage("core")}"); }\n`,
      workspacePath: "packages/tools"
    },
    {
      name: "shared cannot import any workspace package",
      packageName: workspacePackage("shared"),
      source: `import "${workspacePackage("providers")}";\nexport const value = 1;\n`,
      workspacePath: "packages/shared"
    }
  ])("rejects forbidden source edge: $name", async ({ packageName, source, workspacePath }) => {
    await withFixtureWorkspace(async (root) => {
      await writeWorkspacePackage(root, workspacePath, packageName, source);

      const result = runChecker(root);

      expect(result.status).toBe(1);
      expect(result.stderr).toContain("Import boundary check failed");
    });
  });

  it("rejects forbidden package.json workspace dependencies", async () => {
    await withFixtureWorkspace(async (root) => {
      await writeWorkspacePackage(root, "packages/plugin-sdk", workspacePackage("plugin-sdk"), "export const value = 1;\n", {
        [workspacePackage("secrets")]: "workspace:*",
        [workspacePackage("shared")]: "workspace:*"
      });

      const result = runChecker(root);

      expect(result.status).toBe(1);
      expect(result.stderr).toContain(`packages/plugin-sdk/package.json must not import ${workspacePackage("secrets")}`);
    });
  });
});
