// Opaque identifiers Ward generates and stores: vault ids and project ids.
// Both are `crypto.randomUUID()` output, and the grammar is deliberately
// strict — lowercase, version 4, RFC 9562 variant — so an identifier has
// exactly one encoding wherever it is compared, persisted, bound as
// authenticated data, or used to locate a record. An id is a namespace
// label, never a credential or a filesystem path (spec §2, §6.2).

const opaqueIdPattern =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

export function isOpaqueId(value: unknown): value is string {
  return typeof value === "string" && opaqueIdPattern.test(value);
}
