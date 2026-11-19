// The source tripwire for the Linux T26 harness (WCLI-21 B2, the agreed N-4
// settlement). It is LEXICAL: it catches the spellings it lists, and a command
// built at run time cannot be closed lexically at all. The real guarantee is that
// no P1-P4 code path builds a reboot or shutdown command; this only makes the
// obvious ways of adding one loud. It lives in the test tree so the word list is
// not itself part of the code it scans.
import { existsSync, readFileSync, statSync } from "node:fs";
import { dirname, normalize, relative, resolve } from "node:path";

export const root = resolve(import.meta.dir, "..", "..");

export const forbiddenWords = [
  "reboot",
  "shutdown",
  "systemctl",
  "poweroff",
  "halt",
  "init",
  "telinit",
] as const;

// Every spawn call the harness may make, by file and by an anchor the test can
// find: a second spawn inside an allowed file changes the count and goes red.
export const spawnCall =
  /\b(?:spawnSync|spawn|execFileSync|fork)\b|\bBun\s*(?:\.\s*spawn(?:Sync)?\b|\[)/g;
export const allowedSpawns: readonly {
  file: string;
  anchor: RegExp;
  count: number;
}[] = [
  {
    file: "scripts/qualify-linux.ts",
    anchor: /import \{ spawnSync \} from "node:child_process";/g,
    count: 1,
  },
  {
    file: "scripts/qualify-linux.ts",
    anchor: /const run = spawnSync\(command, \[\.\.\.args\], \{/g,
    count: 1,
  },
  {
    // P4's delete of the run directory, by literal path (rows.ts removeRunDirectoryUnder).
    file: "scripts/qualify-linux-rows.ts",
    anchor:
      /const run = Bun\.spawnSync\(\["\/bin\/rm", "-rf", "--", directory\]\);/g,
    count: 1,
  },
  {
    file: "scripts/build.ts",
    anchor:
      /const run = Bun\.spawnSync\(buildCommand\(options\), \{ cwd: root \}\);/g,
    count: 1,
  },
  {
    // The product's ACL removal (macOS), bundled through the key adapters.
    file: "src/adapters/inherited-acl.ts",
    anchor: /import \{ spawnSync \} from "node:child_process";/g,
    count: 1,
  },
  {
    file: "src/adapters/inherited-acl.ts",
    anchor: /const result = spawnSync\("\/bin\/chmod", \["-N", path\]\);/g,
    count: 1,
  },
  {
    // The product's tool runner: the command is the resolved trusted tool path.
    file: "src/adapters/tpm2-tools.ts",
    anchor:
      /return Bun\.spawn\(\[toolPath\(presence, tool\), \.\.\.args\], \{/g,
    count: 1,
  },
];

// The generated interposer text is shell by design (a30): inside interposerScript
// only the CONTENTS of string and template literals are blanked, so it is pinned
// by the golden test instead, while the TypeScript around them is still scanned
// (a spawn, exec, dynamic load or Bun.$ inside the function is a finding). The
// window ends at the function's own closing brace, not at the next export.
export function withoutInterposerText(file: string, source: string): string {
  if (!file.endsWith("qualify-linux-shim.ts")) return source;
  const start = source.indexOf("export function interposerScript(");
  const close = source.indexOf("\n}\n", start);
  if (start === -1 || close === -1)
    throw new Error("interposerScript anchor not found");
  const end = close + 3;
  const body = source
    .slice(start, end)
    .replace(/(["'`])(?:\\[\s\S]|(?!\1)[^\\])*\1/g, "$1$1");
  return source.slice(0, start) + body + source.slice(end);
}

// Comments removed by the transpiler; then the spellings that join or hide a
// word are normalised: "re"+"boot", template pieces, \u and \x escapes.
export function normalise(source: string): string {
  let code = new Bun.Transpiler({ loader: "ts" }).transformSync(source);
  code = code
    .replace(/\\u\{([0-9a-fA-F]+)\}/g, (_, h) =>
      String.fromCodePoint(Number.parseInt(h, 16)),
    )
    .replace(/\\u([0-9a-fA-F]{4})/g, (_, h) =>
      String.fromCharCode(Number.parseInt(h, 16)),
    )
    .replace(/\\x([0-9a-fA-F]{2})/g, (_, h) =>
      String.fromCharCode(Number.parseInt(h, 16)),
    )
    .replace(/\$\{\s*(["'])([^"'`$]*)\1\s*\}/g, "$2");
  for (;;) {
    const joined = code.replace(/["'`]\s*\+\s*["'`]/g, "");
    if (joined === code) return code;
    code = joined;
  }
}

// The forbidden WORDS are checked on the harness's own scripts only: a message or
// a comment-like string in product code under src/ may say "reboot" or "init".
// Every other rule runs over every bundled module.
export function sourceProblems(source: string, words = true): string[] {
  const code = normalise(source);
  const problems: string[] = (words ? forbiddenWords : [])
    .filter((word) => new RegExp(`\\b${word}\\b`).test(code))
    .map((word) => `names ${word}`);
  const found = (name: string, pattern: RegExp): void => {
    if (pattern.test(code)) problems.push(name);
  };
  found("a shell as a command", /["'`](?:[\w.-]*\/)*(?:ba|z|da|k|c)?sh["'`]/);
  found("sh -c in one string", /(?:^|[\s"'`/])(?:ba|z|da)?sh\s+-[a-zA-Z]*c\b/);
  found("a shell shorthand option", /[{,]\s*shell\s*[,}]/);
  found("a shell option", /\bshell\s*:\s*(?!\s)(?!false\b|!1(?![\w.]))/);
  found("a quoted shell option", /["'`]shell["'`]\s*:/);
  found("exec", /\bexecSync\b|\bexecFile\b|(?<![.\w])exec\s*\(/);
  found("a member exec on a process module", /\b(?:cp|child_process)\.exec/);
  found("Bun.$", /\bBun\.\$|(?<=[\s(=,:])\$`/);
  found(
    "a $ taken from bun",
    /import\s*\{[^}]*\$[^}]*\}\s*from\s*["']bun["']|\{\s*\$\s*:/,
  );
  found(
    "a default or namespace child_process import",
    /import\s+(?:\*\s+as\s+)?\w+\s*(?:,\s*\{[^}]*\}\s*)?from\s*["'](?:node:)?child_process["']/,
  );
  found("a dynamic module load", /\brequire\s*\(|\bimport\s*\(/);
  for (const line of code.split("\n"))
    if (/child_process/.test(line) && /\bas\b/.test(line))
      problems.push("an aliased process import");
  return problems;
}

// The relative-import closure of the given roots: every module the compiled
// harness bundles from this repository, so a module imported later is scanned at
// once. A relative specifier that does not resolve THROWS (a scan that read fewer
// inputs than it should must fail); Bun's own extension order is tried first.
const extensions = ["", ".ts", ".tsx", ".js", ".mjs", "/index.ts", "/index.js"];
export function closure(
  entries: readonly string[],
  base: string = root,
): string[] {
  const seen = new Set<string>();
  const queue = [...entries];
  while (queue.length > 0) {
    const file = queue.pop() as string;
    if (seen.has(file)) continue;
    seen.add(file);
    const text = readFileSync(resolve(base, file), "utf8");
    for (const m of text.matchAll(
      /(?:from|import)\s*\(?\s*["'](\.[^"']+)["']/g,
    )) {
      const target = normalize(
        resolve(dirname(resolve(base, file)), m[1] as string),
      );
      const found = extensions
        .map((extension) => target + extension)
        .find((path) => existsSync(path) && statSync(path).isFile());
      if (found === undefined)
        throw new Error(`${file} imports ${m[1]}, which does not resolve`);
      queue.push(relative(base, found));
    }
  }
  return [...seen].sort();
}
