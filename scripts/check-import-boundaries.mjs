#!/usr/bin/env node
import { readdir, readFile, stat } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { pathToFileURL } from "node:url";

const workspacePackageNames = [
  "@dominic-nexus/audit",
  "@dominic-nexus/channels",
  "@dominic-nexus/config",
  "@dominic-nexus/core",
  "@dominic-nexus/logging",
  "@dominic-nexus/memory",
  "@dominic-nexus/permissions",
  "@dominic-nexus/plugin-sdk",
  "@dominic-nexus/providers",
  "@dominic-nexus/secrets",
  "@dominic-nexus/shared",
  "@dominic-nexus/tools",
  "@dominic-nexus/cli"
];

const allowedWorkspaceImports = {
  "@dominic-nexus/audit": ["@dominic-nexus/logging", "@dominic-nexus/shared"],
  "@dominic-nexus/channels": ["@dominic-nexus/shared"],
  "@dominic-nexus/config": ["@dominic-nexus/audit", "@dominic-nexus/plugin-sdk", "@dominic-nexus/shared"],
  "@dominic-nexus/core": [
    "@dominic-nexus/audit",
    "@dominic-nexus/channels",
    "@dominic-nexus/config",
    "@dominic-nexus/logging",
    "@dominic-nexus/memory",
    "@dominic-nexus/permissions",
    "@dominic-nexus/plugin-sdk",
    "@dominic-nexus/providers",
    "@dominic-nexus/secrets",
    "@dominic-nexus/shared",
    "@dominic-nexus/tools"
  ],
  "@dominic-nexus/logging": ["@dominic-nexus/shared"],
  "@dominic-nexus/memory": [
    "@dominic-nexus/audit",
    "@dominic-nexus/logging",
    "@dominic-nexus/permissions",
    "@dominic-nexus/plugin-sdk",
    "@dominic-nexus/shared"
  ],
  "@dominic-nexus/permissions": ["@dominic-nexus/audit", "@dominic-nexus/shared"],
  "@dominic-nexus/plugin-sdk": ["@dominic-nexus/shared"],
  "@dominic-nexus/providers": [
    "@dominic-nexus/audit",
    "@dominic-nexus/logging",
    "@dominic-nexus/permissions",
    "@dominic-nexus/plugin-sdk",
    "@dominic-nexus/secrets",
    "@dominic-nexus/shared"
  ],
  "@dominic-nexus/secrets": [
    "@dominic-nexus/audit",
    "@dominic-nexus/logging",
    "@dominic-nexus/permissions",
    "@dominic-nexus/shared"
  ],
  "@dominic-nexus/shared": [],
  "@dominic-nexus/tools": [
    "@dominic-nexus/audit",
    "@dominic-nexus/logging",
    "@dominic-nexus/memory",
    "@dominic-nexus/permissions",
    "@dominic-nexus/plugin-sdk",
    "@dominic-nexus/secrets",
    "@dominic-nexus/shared"
  ],
  "@dominic-nexus/cli": [
    "@dominic-nexus/audit",
    "@dominic-nexus/channels",
    "@dominic-nexus/config",
    "@dominic-nexus/core",
    "@dominic-nexus/logging",
    "@dominic-nexus/memory",
    "@dominic-nexus/permissions",
    "@dominic-nexus/plugin-sdk",
    "@dominic-nexus/providers",
    "@dominic-nexus/secrets",
    "@dominic-nexus/shared",
    "@dominic-nexus/tools"
  ]
};

const packageRoots = ["apps", "packages"];
const ignoredDirectoryNames = new Set([
  ".cache",
  ".generated",
  ".turbo",
  "build",
  "cache",
  "coverage",
  "dist",
  "generated",
  "node_modules"
]);
const sourceExtensions = new Set([".ts", ".tsx", ".mts", ".cts", ".js", ".jsx", ".mjs", ".cjs"]);
const workspacePackageNameSet = new Set(workspacePackageNames);
const importPattern =
  /\bimport\s+(?:[\s\S]*?\s+from\s*)?["'](@dominic-nexus\/[^"']+)["']|\bexport\s+(?:type\s+)?(?:[\s\S]*?\s+from\s*)["'](@dominic-nexus\/[^"']+)["']|\bimport\s*\(\s*["'](@dominic-nexus\/[^"']+)["']\s*\)/g;

function relative(workspaceRoot, filePath) {
  return path.relative(workspaceRoot, filePath).replaceAll(path.sep, "/");
}

async function pathExists(filePath) {
  try {
    await stat(filePath);
    return true;
  } catch {
    return false;
  }
}

async function readJson(filePath) {
  return JSON.parse(await readFile(filePath, "utf8"));
}

function normalizeWorkspaceSpecifier(specifier) {
  const parts = specifier.split("/");
  return parts.length >= 2 ? `${parts[0]}/${parts[1]}` : specifier;
}

function parseArgs(argv) {
  const rootIndex = argv.indexOf("--root");
  if (rootIndex === -1) {
    return {
      root: process.cwd()
    };
  }

  const root = argv[rootIndex + 1];
  if (root === undefined) {
    throw new Error("--root requires a path");
  }

  return {
    root: path.resolve(root)
  };
}

function getAllowedImports(importerName) {
  return new Set(allowedWorkspaceImports[importerName] ?? []);
}

function assertWorkspaceImportAllowed(importerName, importedName, location) {
  if (importerName === importedName) {
    return undefined;
  }

  if (!workspacePackageNameSet.has(importedName)) {
    return undefined;
  }

  if (getAllowedImports(importerName).has(importedName)) {
    return undefined;
  }

  return `${location} must not import ${importedName} from ${importerName}.`;
}

function findWorkspaceImports(contents) {
  const imports = [];

  for (const match of contents.matchAll(importPattern)) {
    const specifier = match[1] ?? match[2] ?? match[3];
    if (specifier !== undefined) {
      imports.push(normalizeWorkspaceSpecifier(specifier));
    }
  }

  return imports;
}

async function listWorkspacePackages(workspaceRoot) {
  const packages = [];

  for (const packageRoot of packageRoots) {
    const rootPath = path.join(workspaceRoot, packageRoot);
    if (!(await pathExists(rootPath))) {
      continue;
    }

    const entries = await readdir(rootPath, { withFileTypes: true });
    for (const entry of entries) {
      if (!entry.isDirectory()) {
        continue;
      }

      const packageDir = path.join(rootPath, entry.name);
      const packageJsonPath = path.join(packageDir, "package.json");
      if (!(await pathExists(packageJsonPath))) {
        continue;
      }

      const packageJson = await readJson(packageJsonPath);
      if (workspacePackageNameSet.has(packageJson.name)) {
        packages.push({
          dir: packageDir,
          name: packageJson.name,
          packageJson,
          packageJsonPath
        });
      }
    }
  }

  return packages.sort((left, right) => relative(workspaceRoot, left.dir).localeCompare(relative(workspaceRoot, right.dir)));
}

async function listSourceFiles(rootPath) {
  const results = [];
  const entries = await readdir(rootPath, { withFileTypes: true });

  for (const entry of entries) {
    if (ignoredDirectoryNames.has(entry.name)) {
      continue;
    }

    const entryPath = path.join(rootPath, entry.name);

    if (entry.isDirectory()) {
      results.push(...(await listSourceFiles(entryPath)));
      continue;
    }

    if (entry.isFile() && sourceExtensions.has(path.extname(entry.name))) {
      results.push(entryPath);
    }
  }

  return results;
}

function getDeclaredWorkspaceDependencies(packageJson) {
  const dependencyBlocks = [
    packageJson.dependencies,
    packageJson.devDependencies,
    packageJson.peerDependencies,
    packageJson.optionalDependencies
  ];
  const dependencyNames = new Set();

  for (const block of dependencyBlocks) {
    if (block === undefined) {
      continue;
    }

    for (const [name, version] of Object.entries(block)) {
      if (workspacePackageNameSet.has(name) && typeof version === "string" && version.startsWith("workspace:")) {
        dependencyNames.add(name);
      }
    }
  }

  return [...dependencyNames].sort();
}

export async function checkImportBoundaries(options = {}) {
  const workspaceRoot = path.resolve(options.root ?? process.cwd());
  const errors = [];
  const packages = await listWorkspacePackages(workspaceRoot);

  for (const workspacePackage of packages) {
    const packageLabel = relative(workspaceRoot, workspacePackage.packageJsonPath);
    for (const dependencyName of getDeclaredWorkspaceDependencies(workspacePackage.packageJson)) {
      const error = assertWorkspaceImportAllowed(workspacePackage.name, dependencyName, packageLabel);
      if (error !== undefined) {
        errors.push(error);
      }
    }

    const sourceDir = path.join(workspacePackage.dir, "src");
    if (!(await pathExists(sourceDir))) {
      continue;
    }

    const sourceFiles = await listSourceFiles(sourceDir);
    for (const sourceFile of sourceFiles) {
      const sourceLabel = relative(workspaceRoot, sourceFile);
      const contents = await readFile(sourceFile, "utf8");
      for (const importedName of findWorkspaceImports(contents)) {
        const error = assertWorkspaceImportAllowed(workspacePackage.name, importedName, sourceLabel);
        if (error !== undefined) {
          errors.push(error);
        }
      }
    }
  }

  return {
    errors,
    packageCount: packages.length
  };
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  const result = await checkImportBoundaries(options);

  if (result.errors.length > 0) {
    console.error("Import boundary check failed:");
    for (const error of result.errors) {
      console.error(`- ${error}`);
    }
    process.exit(1);
  }

  console.log(`Import boundary check passed for ${result.packageCount} packages.`);
}

const isMain = process.argv[1] !== undefined && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href;

if (isMain) {
  main().catch((error) => {
    console.error(error instanceof Error ? error.message : String(error));
    process.exit(1);
  });
}
