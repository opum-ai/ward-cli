// Which project a checkout may act on, decided in one place. The manifest
// names the project and the vault's binding is the authority, so the two must
// agree: a missing manifest is not-registered, a missing binding is the same
// answer for every caller but the readiness reading (`ward check`, `ward
// profile list`) — which reports it rather than refusing, because reporting
// it is what readiness is for — and a binding naming another project is a
// conflict, never a fallback (docs/adr/0003).
//
// Every command that resolves a project reads the rule from here — `ward
// run`, `ward secret`, `ward profile` and `ward audit` — and so does the
// re-check each write transaction runs, which applies the same rule to the
// project id the earlier read resolved rather than to the manifest. Both
// error codes are raised in one place, so a change to the rule lands once.
import { WardError } from "../contract/errors.ts";
import type { ProjectManifest } from "../domain/project-manifest.ts";
import {
  type BindingRecord,
  type CheckoutIdentity,
  findBinding,
  type VaultState,
} from "../domain/vault-state.ts";
import type { Checkout } from "./project.ts";

// The readiness reading — `ward check` and `ward profile list` — reports an
// unbound checkout instead of refusing it; that is the one reading of the
// rule under which an absent binding is an answer.
export type BindingAuthority =
  | { readonly kind: "bound"; readonly projectId: string }
  | { readonly kind: "unbound" };

// The rule itself: the binding for this checkout, refused the moment it names
// a project other than the expected one. Whether an absent binding is a
// refusal or an answer is the caller's reading, and the only thing the
// readings below differ on.
function bindingNaming(
  state: VaultState,
  identity: CheckoutIdentity,
  expectedProjectId: string,
): BindingRecord | undefined {
  const binding = findBinding(state, identity);
  if (binding !== undefined && binding.projectId !== expectedProjectId)
    throw new WardError("binding_conflict");
  return binding;
}

// The manifest as the checkout declares it, or a refusal: without one there
// is nothing for a binding to agree with and nothing to resolve a project
// from.
export function requireManifest(checkout: Checkout): ProjectManifest {
  if (checkout.manifest === undefined)
    throw new WardError("project_not_registered");
  return checkout.manifest;
}

// The refusing reading, against a project id an earlier read already
// resolved. This is what a write transaction runs: the state a write is about
// to act on may not be the one that was read, and the binding is what
// authorises acting on it at all.
export function requireBinding(
  state: VaultState,
  identity: CheckoutIdentity,
  expectedProjectId: string,
): string {
  const binding = bindingNaming(state, identity, expectedProjectId);
  if (binding === undefined) throw new WardError("project_not_registered");
  return binding.projectId;
}

// The same reading from the checkout: the manifest supplies the expected
// project, and a missing manifest and a missing binding are one answer.
export function boundProject(checkout: Checkout, state: VaultState): string {
  const manifest = requireManifest(checkout);
  return requireBinding(state, checkout.identity, manifest.projectId);
}

// The readiness reading: the same rule, with the absent binding reported
// rather than refused.
export function bindingAuthority(
  checkout: Checkout,
  state: VaultState,
): BindingAuthority {
  const manifest = requireManifest(checkout);
  const binding = bindingNaming(state, checkout.identity, manifest.projectId);
  return binding === undefined
    ? { kind: "unbound" }
    : { kind: "bound", projectId: binding.projectId };
}
