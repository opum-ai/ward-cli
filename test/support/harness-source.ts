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
// the literal text of strings and templates is blanked and pinned by the golden
// test instead, while every `${...}` expression and all the TypeScript around the
// literals stays visible (a spawn, exec, dynamic load or Bun.$ there is a
// finding). It runs on the comment-stripped code, so a quote inside a comment
// cannot pair with another. The window is exactly one function: it ends at the
// function's own closing line and must not contain another export.
function blankLiterals(text: string): string {
  let out = "";
  let i = 0;
  while (i < text.length) {
    const c = text[i] as string;
    if (c === '"' || c === "'") {
      let j = i + 1;
      while (j < text.length && text[j] !== c) j += text[j] === "\\" ? 2 : 1;
      out += c + c;
      i = j + 1;
    } else if (c === "`") {
      out += c;
      i += 1;
      while (i < text.length && text[i] !== "`") {
        if (text[i] === "\\") i += 2;
        else if (text[i] === "$" && text[i + 1] === "{") {
          let depth = 1;
          let j = i + 2;
          while (j < text.length && depth > 0) {
            if (text[j] === "{") depth += 1;
            if (text[j] === "}") depth -= 1;
            j += 1;
          }
          out += text.slice(i, j);
          i = j;
        } else i += 1;
      }
      out += "`";
      i += 1;
    } else {
      out += c;
      i += 1;
    }
  }
  return out;
}

function blankInterposer(code: string): string {
  const start = code.indexOf("export function interposerScript(");
  const close = start === -1 ? -1 : code.indexOf("\n}\n", start);
  if (start === -1 || close === -1)
    throw new Error("interposerScript anchor not found");
  const end = close + 3;
  if (code.slice(start + 1, end).includes("\nexport function"))
    throw new Error("the interposerScript window contains another export");
  return (
    code.slice(0, start) +
    blankLiterals(code.slice(start, end)) +
    code.slice(end)
  );
}

// Comments removed by the transpiler; the interposer window blanked for the
// shim; then the spellings that join or hide a word are normalised: "re"+"boot",
// template pieces, \u and \x escapes.
export function normalise(source: string, file = ""): string {
  let code = new Bun.Transpiler({ loader: "ts" }).transformSync(source);
  if (file.endsWith("qualify-linux-shim.ts")) code = blankInterposer(code);
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

// Words in the harness's own scripts are findings anywhere in the code. In the
// product code under src/ they are findings only as a whole quoted literal or its
// final path component ("/usr/sbin/reboot"), so a message that says "reboot" or
// "init" in prose passes (leader ruling, #410 round 2 finding 2).
export type Words = "anywhere" | "literal";
export function sourceProblems(
  source: string,
  options: { file?: string; words?: Words } = {},
): string[] {
  const code = normalise(source, options.file ?? "");
  const words = options.words ?? "anywhere";
  const problems: string[] = forbiddenWords
    .filter((word) =>
      new RegExp(
        words === "anywhere"
          ? `\\b${word}\\b`
          : `["'\`](?:[\\w.-]*\\/)*${word}["'\`]`,
      ).test(code),
    )
    .map((word) => `names ${word}`);
  const found = (name: string, pattern: RegExp): void => {
    if (pattern.test(code)) problems.push(name);
  };
  found("a shell as a command", /["'`](?:[\w.-]*\/)*(?:ba|z|da|k|c)?sh["'`]/);
  found("sh -c in one string", /\b(?:ba|z|da)?sh\s+-[a-zA-Z]*c\b/);
  found("a shell shorthand option", /[{,]\s*shell\s*[,}]/);
  found("a shell option", /\bshell\s*:\s*(?!\s)(?!false\b|!1(?![\w.]))/);
  found("a quoted shell option", /["'`]shell["'`]\s*:/);
  found("exec", /\bexecSync\b|\bexecFile\b|(?<![.\w])exec\s*\(/);
  found("a member exec on a process module", /\b(?:cp|child_process)\.exec/);
  found("Bun.$", /\bBun\.\$|(?<=[\s(=,:])\$`/);
  found("a $ member", /\w\s*\.\s*\$\s*[`(]/);
  found("a $ alias", /[=(,]\s*\$\s*[;,)]/);
  found(
    "a $ taken from bun",
    /import\s*\{[^}]*\$[^}]*\}\s*from\s*["']bun["']|\{\s*\$\s*[,}:]/,
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
// inputs than it should must fail); every extension Bun may try is looked for.
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
        .filter((path) => existsSync(path) && statSync(path).isFile());
      if (found.length === 0)
        throw new Error(`${file} imports ${m[1]}, which does not resolve`);
      // Which one Bun bundles depends on its extension order, so a second
      // candidate is refused rather than guessed at.
      if (found.length > 1)
        throw new Error(
          `${file} imports ${m[1]}, which resolves to ${found.length} files`,
        );
      queue.push(relative(base, found[0] as string));
    }
  }
  return [...seen].sort();
}
