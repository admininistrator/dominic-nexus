#!/usr/bin/env node
import { readdir, readFile, stat } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { checkImportBoundaries } from "./check-import-boundaries.mjs";

const workspaceRoot = process.cwd();
const packageRoots = ["apps", "packages"];
const requiredScripts = ["build", "typecheck", "test", "lint", "clean"];
const expectedPackageLint = "tsc -p tsconfig.json --noEmit";
const forbiddenSourceMarkers = ["reference-openclaw"];
const forbiddenWorkspaceEntries = ["dist", "build", "coverage", ".cache", ".turbo"];

const errors = [];

async function readJson(filePath) {
  try {
    return JSON.parse(await readFile(filePath, "utf8"));
  } catch (error) {
    errors.push(`${relative(filePath)} is not valid JSON: ${error.message}`);
    return undefined;
  }
}

async function pathExists(filePath) {
  try {
    await stat(filePath);
    return true;
  } catch {
    return false;
  }
}

function relative(filePath) {
  return path.relative(workspaceRoot, filePath).replaceAll(path.sep, "/");
}

async function listWorkspacePackages() {
  const packageDirs = [];

  for (const packageRoot of packageRoots) {
    const rootPath = path.join(workspaceRoot, packageRoot);
    const entries = await readdir(rootPath, { withFileTypes: true });

    for (const entry of entries) {
      if (!entry.isDirectory()) {
        continue;
      }

      const packageDir = path.join(rootPath, entry.name);
      if (await pathExists(path.join(packageDir, "package.json"))) {
        packageDirs.push(packageDir);
      }
    }
  }

  return packageDirs.sort((left, right) => relative(left).localeCompare(relative(right)));
}

async function listFiles(rootPath) {
  const results = [];
  const entries = await readdir(rootPath, { withFileTypes: true });

  for (const entry of entries) {
    const entryPath = path.join(rootPath, entry.name);

    if (entry.isDirectory()) {
      results.push(...(await listFiles(entryPath)));
      continue;
    }

    if (entry.isFile()) {
      results.push(entryPath);
    }
  }

  return results;
}

async function checkRootPackage() {
  const packageJsonPath = path.join(workspaceRoot, "package.json");
  const packageJson = await readJson(packageJsonPath);

  if (packageJson === undefined) {
    return;
  }

  const lintScript = packageJson.scripts?.lint;
  if (lintScript !== "node scripts/lint-workspace.mjs && pnpm -r lint") {
    errors.push("Root lint script must run scripts/lint-workspace.mjs before package lint scripts.");
  }
}

async function checkPackage(packageDir) {
  const packageJsonPath = path.join(packageDir, "package.json");
  const tsconfigPath = path.join(packageDir, "tsconfig.json");
  const indexPath = path.join(packageDir, "src", "index.ts");
  const label = relative(packageDir);

  const packageJson = await readJson(packageJsonPath);

  if (!(await pathExists(tsconfigPath))) {
    errors.push(`${label} is missing tsconfig.json.`);
  }

  if (!(await pathExists(indexPath))) {
    errors.push(`${label} is missing src/index.ts.`);
  }

  if (packageJson === undefined) {
    return;
  }

  if (packageJson.private !== true) {
    errors.push(`${label}/package.json must stay private.`);
  }

  if (packageJson.type !== "module") {
    errors.push(`${label}/package.json must declare ESM with "type": "module".`);
  }

  for (const scriptName of requiredScripts) {
    if (typeof packageJson.scripts?.[scriptName] !== "string") {
      errors.push(`${label}/package.json is missing scripts.${scriptName}.`);
    }
  }

  if (packageJson.scripts?.lint !== expectedPackageLint) {
    errors.push(`${label}/package.json lint must be "${expectedPackageLint}".`);
  }
}

async function checkForbiddenWorkspaceEntries() {
  for (const packageRoot of packageRoots) {
    const rootPath = path.join(workspaceRoot, packageRoot);
    const packageDirs = await readdir(rootPath, { withFileTypes: true });

    for (const packageDir of packageDirs) {
      if (!packageDir.isDirectory()) {
        continue;
      }

      const packagePath = path.join(rootPath, packageDir.name);
      const entries = await readdir(packagePath, { withFileTypes: true });

      for (const entry of entries) {
        if (entry.isDirectory() && forbiddenWorkspaceEntries.includes(entry.name)) {
          errors.push(`${relative(path.join(packagePath, entry.name))}/ must not be committed or used as source input.`);
        }
      }
    }
  }
}

async function checkSourceMarkers() {
  const sourceRoots = [
    path.join(workspaceRoot, "apps"),
    path.join(workspaceRoot, "packages")
  ];

  for (const sourceRoot of sourceRoots) {
    const files = await listFiles(sourceRoot);

    for (const filePath of files) {
      if (![".ts", ".mts", ".cts", ".js", ".mjs", ".cjs"].includes(path.extname(filePath))) {
        continue;
      }

      const contents = await readFile(filePath, "utf8");
      for (const marker of forbiddenSourceMarkers) {
        if (contents.includes(marker)) {
          errors.push(`${relative(filePath)} must not import or depend on ${marker}.`);
        }
      }
    }
  }
}

await checkRootPackage();
const packageDirs = await listWorkspacePackages();
for (const packageDir of packageDirs) {
  await checkPackage(packageDir);
}
await checkForbiddenWorkspaceEntries();
await checkSourceMarkers();
const boundaryResult = await checkImportBoundaries({ root: workspaceRoot });
errors.push(...boundaryResult.errors);

if (errors.length > 0) {
  console.error("Workspace lint failed:");
  for (const error of errors) {
    console.error(`- ${error}`);
  }
  process.exit(1);
}

console.log(`Workspace lint passed for ${packageDirs.length} packages.`);
