// How Ward renders a value for a human to read (spec §9.2, §4.3).
//
// Two surfaces show values a developer has to judge: the interactive approval
// prompt, which has to show the operation being approved, and the text
// reports `ward profile list` and `ward check` print. The values on both
// come from a tracked manifest — a file anyone who can edit the repository
// can write, an agent included — so a value can carry terminal control or
// format characters: sequences that erase the line above, retitle the
// window, or reorder text so the host shown is not the host Ward would
// actually use.
//
// Escaping is the policy and it is pure — no I/O, no state — which is why it
// lives in the domain layer rather than beside either renderer. Escaped are
// every code point below 0x20, DEL, the C1 range (0x80 to 0x9f, where the
// eight-bit CSI U+009B sits), Unicode's Format (Cf) category — the bidi
// overrides and zero-width characters among them — the line and paragraph
// separators, and every space separator (Zs) other than the ordinary ASCII
// space. Ordinary ASCII space is escaped too when it appears in a run, so a
// padded value cannot be used as layout: whitespace cannot push the real
// destination of an operation off screen (WCLI-100). Each becomes a printable
// escape, so what is shown is readable and cannot act on the terminal that
// shows it: every code point that can move a cursor, end a line, reverse text
// or pad a line is shown as text.
const invisibleCharacter = /[\p{Cf}\p{Zl}\p{Zp}]/u;
const spaceSeparator = /^\p{Zs}$/u;

// One source code point as the printable chunk that stands for it.
function escapeCharacter(character: string, paddedSpace: boolean): string {
  const code = character.codePointAt(0) ?? 0;
  if (code < 0x20 || (code >= 0x7f && code <= 0x9f))
    return `\\x${code.toString(16).padStart(2, "0")}`;
  // An ordinary ASCII space is harmless alone and is shown as-is so prose and
  // paths stay readable; in a run it is layout, and padding is what WCLI-100
  // closes. Every other space separator (NBSP and its look-alikes) is
  // invisible laid against text, so it is escaped even on its own.
  if (code === 0x20) return paddedSpace ? "\\x20" : " ";
  if (invisibleCharacter.test(character) || spaceSeparator.test(character))
    return code <= 0xffff
      ? `\\u${code.toString(16).padStart(4, "0")}`
      : `\\u{${code.toString(16)}}`;
  return character;
}

export interface EscapeForDisplayLimits {
  // Cap the length of the escaped result, in characters. Truncation is
  // display-only: the caller still holds the full value, and the result ends
  // with "..." so a shortened value is visibly shortened. Never splits an
  // escape sequence.
  readonly maxChars?: number;
}

export function escapeForDisplay(
  value: string,
  limits: EscapeForDisplayLimits = {},
): string {
  const maxChars = limits.maxChars;
  const budget = maxChars === undefined ? Infinity : Math.max(0, maxChars - 3);
  let escaped = "";
  const characters = [...value];
  for (let index = 0; index < characters.length; index++) {
    const character = characters[index] as string;
    const padded =
      character === " " &&
      (characters[index - 1] === " " || characters[index + 1] === " ");
    const chunk = escapeCharacter(character, padded);
    if (escaped.length + chunk.length > budget) return `${escaped}...`;
    escaped += chunk;
  }
  return escaped;
}
