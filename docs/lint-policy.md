# Dominic Nexus lint policy

Last updated: 2026-05-07

`dominic-nexus` intentionally keeps linting lightweight while the scaffold is
small. No lint dependency was added for P01-T05.

`pnpm.cmd lint` runs two checks:

1. `node scripts/lint-workspace.mjs`
   - verifies every workspace package has the expected TypeScript package
     scripts;
   - requires package-level `lint` to run `tsc -p tsconfig.json --noEmit`;
   - checks packages remain private ESM packages with `tsconfig.json` and
     `src/index.ts`;
   - rejects generated output folders under workspace packages;
   - rejects source-level dependency markers for `reference-openclaw`.
2. `pnpm -r lint`
   - runs TypeScript `--noEmit` checks in every package.

This gives useful signal without introducing ESLint or formatter dependencies
before the package boundaries stabilize. A future task can replace or extend
this with TypeScript-aware ESLint once there is enough code to justify the
extra dependency and rule configuration.
