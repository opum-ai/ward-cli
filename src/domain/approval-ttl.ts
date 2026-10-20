// How long a profile approval lasts (DEC-217 Q5, docs/adr/0021).
//
// An approval is a bearer capability for any process running as the developer,
// so it carries an expiry and does not last until revoked. The default is 24
// hours; `--ttl` at approval names another lifetime in a closed grammar — a
// whole number and one unit, m, h or d — so a value is either exactly what the
// developer typed or refused, and nothing is guessed from free text.
//
// The bounds are a build detail and are stated here rather than implied: an
// approval shorter than a minute could expire before the developer's next
// command, and one longer than 30 days is a durable approval under another
// name, which is the case this expiry exists to end.
export const defaultApprovalTtlMs = 24 * 60 * 60 * 1000;
export const minApprovalTtlMs = 60 * 1000;
export const maxApprovalTtlMs = 30 * 24 * 60 * 60 * 1000;

const ttlPattern = /^([1-9][0-9]{0,5})(m|h|d)$/;
const unitMs = { m: 60 * 1000, h: 60 * 60 * 1000, d: 24 * 60 * 60 * 1000 };

// The lifetime in milliseconds, or undefined when the text is not in the
// grammar or is outside the bounds.
export function parseApprovalTtl(text: string): number | undefined {
  const match = ttlPattern.exec(text);
  if (match === null) return undefined;
  const amount = Number(match[1]);
  const unit = match[2] as keyof typeof unitMs;
  const ms = amount * unitMs[unit];
  return ms >= minApprovalTtlMs && ms <= maxApprovalTtlMs ? ms : undefined;
}
