// WCLI-34: Bun strips a binding named `declare` out of a TypeScript file as
// if it were an ambient declaration, and says nothing.
//
// Measured on bun 1.3.14 rather than taken from the report, with the same
// content run four ways:
//   - `function declare(value: string): void { console.log("ran", value); }`
//     followed by `declare("hello")` prints NOTHING and exits 0;
//   - the same file with the name changed prints "ran hello";
//   - `const declare = (value) => { ... }; declare("hello")` prints NOTHING;
//   - the same content as .js prints, and a member call such as
//     `holder.declare("hello")` prints, so it is the bare name in a .ts file
//     that is stripped rather than the name itself.
// A nested `function declare` inside another function is stripped too, which
// is why this scans at any indentation: the report called it a top-level
// hazard, and the measurement says it is not only that.
//
// This is why the guard exists here rather than only upstream: the whole test
// suite is Bun-run TypeScript, and a helper that silently does not run is
// worse than one that fails - an assertion behind it can pass vacuously.
//
// What it checks, over the tracked .ts files:
//   - a definition named `declare` (function, const, let, var, class, or an
//     import binding), at any indentation;
//   - a bare call `declare(...)`, which is the half that silently does
//     nothing when the definition has been stripped.
// It does NOT flag the legitimate keyword uses - `declare const x: number`,
// `declare function f(): void`, `declare module "..."` - which is the shape a
// repository is most likely to contain by accident.
//
// Comments and the contents of strings and template literals are masked
// before matching, so prose or a test's expected-output literal cannot trip
// it. One measured limit that masking creates: a call inside a template
// interpolation (`${declare("x")}`) is masked with the template and not
// seen. The definition that call needs would still be reported, so no file
// passes this check with a stripped helper definition in it.
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { relative } from "node:path";

const root = process.cwd();
const given = process.argv.slice(2);

// The tracked files, so an untracked scratch file is not the check's business
// and a file that is added is covered the moment it is staged.
function trackedTypeScript(cwd) {
  const listed = execFileSync("git", ["ls-files", "*.ts"], {
    cwd,
    encoding: "utf8",
  });
  return listed.split("\n").filter((line) => line.length > 0);
}

// Every character inside a comment, a string or a template is replaced by a
// space, keeping newlines, so the offsets and line numbers of the code that
// remains are exactly the file's own.
function maskNonCode(source) {
  const out = source.split("");
  let state = "code";
  const blank = (index) => {
    if (out[index] !== "\n") out[index] = " ";
  };
  for (let i = 0; i < source.length; i++) {
    const char = source[i];
    const next = source[i + 1];
    switch (state) {
      case "code":
        if (char === "/" && next === "/") {
          state = "line";
          blank(i);
        } else if (char === "/" && next === "*") {
          state = "block";
          blank(i);
        } else if (char === '"' || char === "'" || char === "`") {
          state = char;
          blank(i);
        }
        break;
      case "line":
        if (char === "\n") state = "code";
        else blank(i);
        break;
      case "block":
        blank(i);
        if (char === "*" && next === "/") {
          blank(i + 1);
          i++;
          state = "code";
        }
        break;
      default:
        // Inside a string or template: an escape consumes the next character,
        // so a backslash before the closing quote does not end it.
        blank(i);
        if (char === "\\") {
          blank(i + 1);
          i++;
        } else if (char === state) {
          state = "code";
        }
        break;
    }
  }
  return out.join("");
}

const definition =
  /^[ \t]*(?:export[ \t]+)?(?:default[ \t]+)?(?:async[ \t]+)?(?:function|const|let|var|class)[ \t]+declare\b/;
const importBinding = /^[ \t]*(?:import|export)[^\n]*\bdeclare\b[^\n]*\bfrom\b/;
// A bare call: `declare(` not preceded by a dot or an identifier character.
// `declare function f()` and `declare const x` do not match, because the
// keyword forms are always followed by another keyword rather than by "(".
const bareCall = /(^|[^.\w$])declare[ \t]*\(/;

function findings(path) {
  const masked = maskNonCode(readFileSync(path, "utf8"));
  const found = [];
  // A file inside the repository reads as its repository-relative path; one
  // handed in from outside (the test's fixtures) reads as the path it was
  // given, rather than as a chain of `../`.
  const shown = path.startsWith(root) ? relative(root, path) : path;
  masked.split("\n").forEach((line, index) => {
    const at = `${shown}:${index + 1}`;
    if (definition.test(line))
      found.push(`${at}: defines a binding named declare`);
    else if (importBinding.test(line))
      found.push(`${at}: imports a binding named declare`);
    else if (bareCall.test(line))
      found.push(`${at}: calls declare as a bare identifier`);
  });
  return found;
}

const files = given.length > 0 ? given : trackedTypeScript(root);
const problems = files.flatMap((path) => findings(path));

if (problems.length > 0) {
  console.error(
    [
      "Bun strips a binding named declare out of a .ts file, and its calls",
      "with it, without a diagnostic (WCLI-34). Rename the binding:",
      "",
      ...problems.map((problem) => `  ${problem}`),
    ].join("\n"),
  );
  process.exit(1);
}

console.log(
  `reserved binding check: ${files.length} file(s), 0 bindings named declare`,
);
