// `ward init`'s instruction-file multiselect, rendered by @clack/prompts on
// the same terms the peer CLIs ask it (DEC-48, DEC-52, ADR 0016): same
// library, same wording, same required:false semantics where a bare Enter
// writes nothing, nothing pre-checked, and the prompt on stderr - never on
// stdout, which is the machine-readable result channel here the way it is in
// lore-cli. The gate is DEC-52's: stdin and stderr must both be interactive
// terminals, because a prompt on a redirected stream is a prompt nobody can
// answer. The choice is the two documents a bridge writes, CLAUDE.md and
// AGENTS.md, and the labels are lore-cli's own for those two.
//
// Everything the terminal supplies arrives through `parts`, so a test drives
// the gate and the cancel mapping without a TTY; the clack call itself is the
// one line only a real terminal exercises.
import { multiselect } from "@clack/prompts";
import type { InstructionFileChooser } from "../application/instruction-choice.ts";
import type { AgentTarget } from "../contract/manifest.ts";

export interface InstructionChoiceQuestion {
  readonly message: string;
  readonly options: readonly {
    readonly label: string;
    readonly value: AgentTarget;
  }[];
  readonly required: false;
}

export interface TerminalChoiceParts {
  stdinIsTty?: () => boolean;
  stderrIsTty?: () => boolean;
  ask?: (
    question: InstructionChoiceQuestion,
  ) => Promise<readonly AgentTarget[] | symbol>;
}

// Word for word the question the peers ask (DEC-48: "use the same pattern"
// includes the same wording - lore-cli's comment names the shared pattern as
// the same library, wording, required:false semantics and cancel handling).
const message =
  "Select instruction files to write (space toggles, enter accepts)";

// The two labels are lore-cli's own for these files. Ward supports exactly
// the two hosts its bridge does; the peers' extra targets (hermes,
// antigravity) name files Ward has no block for, so they are absent rather
// than offered and refused.
const options: InstructionChoiceQuestion["options"] = [
  { label: "CLAUDE.md — Claude Code", value: "claude" },
  {
    label:
      "AGENTS.md — Codex, Cursor, Zed, Warp, Aider, RooCode, OpenCode, pi, and other AGENTS.md-reading tools",
    value: "codex",
  },
];

// The real prompt. `input`/`output` are explicit rather than clack's
// defaults: stdout must not carry the prompt (see the header), so the UI
// renders on stderr while the keys come from stdin. A stream that ends while
// the prompt is open aborts through clack's own cancellation path instead of
// hanging - the guard lore-cli added for the same library (LCLI-462).
async function askClack(
  question: InstructionChoiceQuestion,
): Promise<readonly AgentTarget[] | symbol> {
  const controller = new AbortController();
  const onEnd = () => controller.abort();
  process.stdin.once("end", onEnd);
  try {
    return await multiselect<AgentTarget>({
      message: question.message,
      options: question.options.map((option) => ({
        label: option.label,
        value: option.value,
      })),
      required: question.required,
      input: process.stdin,
      output: process.stderr,
      signal: controller.signal,
    });
  } finally {
    process.stdin.off("end", onEnd);
  }
}

export function createTerminalInstructionChoice(
  parts: TerminalChoiceParts = {},
): InstructionFileChooser {
  const stdinIsTty = parts.stdinIsTty ?? (() => process.stdin.isTTY === true);
  const stderrIsTty =
    parts.stderrIsTty ?? (() => process.stderr.isTTY === true);
  const ask = parts.ask ?? askClack;
  const available = (): boolean => {
    try {
      return stdinIsTty() && stderrIsTty();
    } catch {
      return false;
    }
  };

  return {
    available,
    async choose() {
      if (!available()) return undefined;
      try {
        const result = await ask({ message, options, required: false });
        // Ctrl-C, an aborted stream, and a terminal that failed mid-prompt
        // all land here as "no answer", never as an empty selection: nothing
        // the developer could not read is treated as a decision.
        return typeof result === "symbol" ? undefined : result;
      } catch {
        return undefined;
      }
    },
  };
}
