// `ward init`'s choice of instruction files (DEC-44, DEC-48, DEC-52): a
// multiselect over CLAUDE.md and AGENTS.md, asked only when a terminal can
// answer it. This interface is the seam, so the command depends on the
// question rather than on the prompt library, and a test answers with a
// scripted choice instead of a terminal.
import type { AgentTarget } from "../contract/manifest.ts";

export interface InstructionFileChooser {
  // Whether the question can be asked at all. DEC-52: both stdin and stderr
  // must be interactive terminals - the prompt renders on stderr, and a
  // stream the reader cannot see is a question nobody can answer.
  available(): boolean;
  // The chosen files, in the order the terminal reported them; undefined
  // when the question was cancelled. A cancel is deliberately not an empty
  // selection: an empty selection is a decision ("write no bridge"), and the
  // caller must not treat an interrupted question as one.
  choose(): Promise<readonly AgentTarget[] | undefined>;
}
