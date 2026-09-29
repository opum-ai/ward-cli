// Ward's managed block in an instruction file (spec §11.2). Ward owns
// exactly the bytes between its own marker pair, and every other byte in the
// file — user prose, and the blocks Lore, Quest and other tools manage — is
// carried through untouched. The transform is pure text so it can be tested
// against the awkward shapes (CRLF, no trailing newline, a marker the user
// indented) without a filesystem.
//
// A marker is a line whose trimmed text is exactly the marker. Anything else
// is the user's text: a near-miss is not a marker Ward acts on, and a
// half-pair, a duplicate, or a pair in the wrong order is a conflict rather
// than something to guess at and then overwrite.
import { WardError } from "../contract/errors.ts";

export const managedBlockBegin = "<!-- ward:begin -->";
export const managedBlockEnd = "<!-- ward:end -->";

export interface ManagedBlockUpdate {
  readonly text: string;
  readonly status: "created" | "updated" | "unchanged";
}

interface LineSpan {
  readonly start: number;
  // Offset just past the line's newline, or the end of the text.
  readonly end: number;
}

function lineSpans(text: string): LineSpan[] {
  const spans: LineSpan[] = [];
  let start = 0;
  for (let index = 0; index < text.length; index++) {
    if (text[index] === "\n") {
      spans.push({ start, end: index + 1 });
      start = index + 1;
    }
  }
  if (start < text.length) spans.push({ start, end: text.length });
  return spans;
}

function markerSpans(text: string, marker: string): LineSpan[] {
  return lineSpans(text).filter(
    (span) => text.slice(span.start, span.end).trim() === marker,
  );
}

// The block is written as its own paragraph: a blank line separates it from
// whatever the file already ended with.
export function upsertManagedBlock(
  text: string,
  body: string,
): ManagedBlockUpdate {
  const inner = body.endsWith("\n") ? body : `${body}\n`;
  const located = locateBlock(text);

  if (located === undefined) {
    const separator =
      text.length === 0 ? "" : text.endsWith("\n") ? "\n" : "\n\n";
    const block = `${managedBlockBegin}\n${inner}${managedBlockEnd}\n`;
    return {
      text: `${text}${separator}${block}`,
      status: text.length === 0 ? "created" : "updated",
    };
  }
  const { begin, end } = located;
  const next = `${text.slice(0, begin.end)}${inner}${text.slice(end.start)}`;
  return { text: next, status: next === text ? "unchanged" : "updated" };
}

// The marker rules every caller shares: a pair is located only when there is
// exactly one of each, in order, and anything else is a conflict. Writing a
// block and judging one therefore cannot drift apart.
function locateBlock(
  text: string,
): { begin: LineSpan; end: LineSpan } | undefined {
  const begins = markerSpans(text, managedBlockBegin);
  const ends = markerSpans(text, managedBlockEnd);
  if (begins.length > 1 || ends.length > 1)
    throw new WardError("instructions_markers_conflict");
  if (begins.length !== ends.length)
    throw new WardError("instructions_markers_conflict");
  const begin = begins[0];
  const end = ends[0];
  if (begin === undefined || end === undefined) return undefined;
  if (begin.start >= end.start)
    throw new WardError("instructions_markers_conflict");
  return { begin, end };
}

export type ManagedBlockState = "absent" | "current" | "stale";

// What is in the file, without changing it: no block is "absent", a block
// whose bytes are exactly what this build writes is "current", and any other
// block is "stale". Malformed markers throw the same conflict the writer
// would, because a file Ward refuses to write is one it also cannot judge.
export function managedBlockStatus(
  text: string,
  body: string,
): ManagedBlockState {
  const inner = body.endsWith("\n") ? body : `${body}\n`;
  const located = locateBlock(text);
  if (located === undefined) return "absent";
  const content = text.slice(located.begin.end, located.end.start);
  return content === inner ? "current" : "stale";
}
