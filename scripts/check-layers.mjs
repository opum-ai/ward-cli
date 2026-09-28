// Enforces the import direction between source layers: cli may use adapters,
// application and contract; adapters (credential store, and later
// filesystem and network) may use application, domain and contract;
// application may use domain and contract; domain
// (pure policy and cryptography; no I/O by convention, which this script does
// not check) may use contract, and contract is a leaf. Imports that leave
// src/ (package.json) are not checked here.
import { readdir, readFile } from "node:fs/promises";
import { dirname, extname, join, normalize, relative } from "node:path";

const sourceRoot = "src";
const allowedDependencies = new Map([
  ["cli", new Set(["adapters", "application", "contract"])],
  ["adapters", new Set(["application", "domain", "contract"])],
  ["application", new Set(["domain", "contract"])],
  ["domain", new Set(["contract"])],
  ["contract", new Set()],
]);

async function collectTypeScriptFiles(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  const files = await Promise.all(
    entries.map(async (entry) => {
      const path = join(directory, entry.name);
      if (entry.isDirectory()) return collectTypeScriptFiles(path);
      return extname(entry.name) === ".ts" ? [path] : [];
    }),
  );
  return files.flat();
}

function layerFor(path) {
  return normalize(path).split(/[\\/]/u)[0];
}

function relativeImportTargets(source) {
  return [
    ...source.matchAll(/(?:from\s*|import\s*\(?\s*)["'](\.[^"']+)["']/g),
  ].map(([, target]) => target);
}

// Native bindings reach the OS directly, so only adapters may import them.
const nativePackages = new Set(["@napi-rs/keyring"]);

function packageImportTargets(source) {
  return [
    ...source.matchAll(/(?:from\s*|import\s*\(?\s*)["']([^."'][^"']*)["']/g),
  ].map(([, target]) => target);
}

const files = await collectTypeScriptFiles(sourceRoot);
const violations = [];

for (const file of files) {
  const sourcePath = normalize(relative(sourceRoot, file));
  const sourceLayer = layerFor(sourcePath);
  const allowed = allowedDependencies.get(sourceLayer);
  if (allowed === undefined) {
    violations.push(
      `${file}: layer "${sourceLayer}" is not declared in scripts/check-layers.mjs`,
    );
    continue;
  }
  const source = await readFile(file, "utf8");
  for (const target of packageImportTargets(source))
    if (nativePackages.has(target) && sourceLayer !== "adapters")
      violations.push(
        `${file}: only adapters may import the native binding ${target}`,
      );
  for (const target of relativeImportTargets(source)) {
    const targetPath = relative(sourceRoot, join(dirname(file), target));
    if (targetPath.startsWith("..")) continue;
    const targetLayer = layerFor(targetPath);
    if (targetLayer !== sourceLayer && !allowed.has(targetLayer)) {
      violations.push(
        `${file}: ${sourceLayer} must not import ${targetLayer} (${target})`,
      );
    }
  }
}

if (violations.length > 0) {
  console.error(violations.join("\n"));
  process.exit(1);
}
console.log(`layer check: ${files.length} files, 0 violations`);
