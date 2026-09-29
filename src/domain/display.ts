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
// every code point below 0x20, DEL, and Unicode's Format (Cf) category: the
// bidi overrides and zero-width characters among them, which a terminal may
// honour without printing anything. Each becomes a printable escape, so what
// is shown is readable and cannot act on the terminal that shows it.
const formatCharacter = /\p{Cf}/u;

export function escapeForDisplay(value: string): string {
  let escaped = "";
  for (const character of value) {
    const code = character.codePointAt(0) ?? 0;
    if (code < 0x20 || code === 0x7f)
      escaped += `\\x${code.toString(16).padStart(2, "0")}`;
    else if (formatCharacter.test(character))
      escaped +=
        code <= 0xffff
          ? `\\u${code.toString(16).padStart(4, "0")}`
          : `\\u{${code.toString(16)}}`;
    else escaped += character;
  }
  return escaped;
}
