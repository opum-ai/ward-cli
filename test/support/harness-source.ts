// The source tripwire for the Linux T26 harness (WCLI-21 B2, the agreed N-4
// settlement). It is LEXICAL: it catches the spellings it lists, and a command
// built at run time cannot be closed lexically at all. The real guarantee is that
// no P1-P4 code path builds a reboot or shutdown command; this only makes the
// obvious ways of adding one loud. It lives in the test tree so the word list is
// not itself part of the code it scans.
import { existsSync, readFileSync } from "node:fs";
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
  /\b(?:spawnSync|spawn|execFileSync|fork|Bun\.spawnSync|Bun\.spawn)\s*\(/g;
export const allowedSpawns: readonly {
  file: string;
  anchor: RegExp;
  count: number;
}[] = [
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
];

// The generated interposer text is shell by design (a30): it is excluded from the
// scan here and pinned by the golden test instead.
export function withoutInterposerText(file: string, source: string): string {
  if (!file.endsWith("qualify-linux-shim.ts")) return source;
  const start = source.indexOf("export function interposerScript(");
  const end = source.indexOf("\nexport function", start + 1);
  if (start === -1 || end === -1)
    throw new Error("interposerScript anchor not found");
  return source.slice(0, start) + source.slice(end);
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
    const joined = code.replace(/(["'`])\s*\+\s*\1/g, "");
    if (joined === code) return code;
    code = joined;
  }
}

export function sourceProblems(source: string): string[] {
  const code = normalise(source);
  const problems: string[] = forbiddenWords
    .filter((word) => new RegExp(`\\b${word}\\b`).test(code))
    .map((word) => `names ${word}`);
  const found = (name: string, pattern: RegExp): void => {
    if (pattern.test(code)) problems.push(name);
  };
  found("a shell as a command", /["'`](?:ba|z|da|k|c)?sh["'`]/);
  found("sh -c in one string", /\b(?:ba|z|da)?sh\s+-[a-zA-Z]*c\b/);
  found("a shell option", /\bshell\s*:\s*(?!\s)(?!false\b|!1(?![\w.]))/);
  found("a quoted shell option", /["'`]shell["'`]\s*:/);
  found("exec", /\bexecSync\b|\bexecFile\b|(?<![.\w])exec\s*\(/);
  found("a member exec on a process module", /\b(?:cp|child_process)\.exec/);
  found("Bun.$", /\bBun\.\$|(?<=[\s(=,:])\$`/);
  found("a dynamic module load", /\brequire\s*\(|\bimport\s*\(/);
  for (const line of code.split("\n"))
    if (/child_process/.test(line) && /\bas\b/.test(line))
      problems.push("an aliased process import");
  return problems;
}

// The relative-import closure of an entry: every module the compiled harness
// bundles from this repository, so a module imported later is scanned at once.
export function closure(entry: string): string[] {
  const seen = new Set<string>();
  const queue = [entry];
  while (queue.length > 0) {
    const file = queue.pop() as string;
    if (seen.has(file)) continue;
    seen.add(file);
    const text = readFileSync(resolve(root, file), "utf8");
    for (const m of text.matchAll(
      /(?:from|import)\s*\(?\s*["'](\.[^"']+)["']/g,
    )) {
      const next = relative(
        root,
        normalize(resolve(dirname(resolve(root, file)), m[1] as string)),
      );
      if (existsSync(resolve(root, next))) queue.push(next);
    }
  }
  return [...seen].sort();
}
