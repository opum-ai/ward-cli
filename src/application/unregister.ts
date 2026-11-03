// `ward unregister`: withdraw this checkout's access (DEC-217 Q4, docs/adr/0022).
//
// Registration is how a checkout gains a project's secrets; this is the other
// half, the developer's way to take it back. It is interactive and narrow: it
// removes the binding for the directory it is run in — matched by path, device,
// inode and the checkout nonce, exactly as a binding is matched everywhere, plus
// a 0.1.1 binding of the same project at that directory, which has no nonce and
// matches nothing (DEC-255 a7) — and never another root's binding, whatever
// project it names. Its approvals are matched the same way plus the project.
// Removing the binding is one confirmation. Removing that binding's profile approvals is a second one,
// asked only when there are some, and declining it keeps them.
//
// What declining leaves behind is stated rather than hidden: an approval is
// bound to a clone's identity, so registering the same clone again revives an
// approval this version wrote and kept, and never one an earlier version wrote.
// A developer who wants the directory to start clean answers yes to both.
//
// Nothing here reads a value, and it needs no manifest: the binding is the
// authority being withdrawn, and a checkout whose manifest was deleted or
// changed is exactly one a developer may want to unregister.
import type { ResultKind } from "../contract/envelope.ts";
import { WardError } from "../contract/errors.ts";
import {
  type BindingRecord,
  type CheckoutIdentity,
  findBinding,
  legacyBindingsAt,
  type ProfileApprovalRecord,
  parseVaultState,
  serializeVaultState,
  type VaultState,
} from "../domain/vault-state.ts";
import type { UnregisterApprover } from "./approvals.ts";
import type { KeyProvider } from "./key-provider.ts";
import type { VaultStore } from "./vault-store.ts";

export interface UnregisterOptions {
  readonly checkout: CheckoutIdentity;
  readonly store: VaultStore;
  readonly keyProvider: KeyProvider;
  readonly approver: UnregisterApprover;
}

export interface UnregisterResult {
  readonly kind: ResultKind;
  readonly data: Record<string, unknown>;
  readonly text: string;
}

// An approval belongs to a binding when it names the same project and all of the
// same directory identity and the same checkout nonce: "that binding's approvals" (DEC-217
// Q4). Another checkout of the project keeps its own, and so does an approval
// of a different project recorded at this identity.
function belongsTo(
  approval: ProfileApprovalRecord,
  binding: BindingRecord,
): boolean {
  return (
    approval.projectId === binding.projectId &&
    approval.root === binding.root &&
    approval.device === binding.device &&
    approval.inode === binding.inode &&
    approval.checkoutId === binding.checkoutId
  );
}

function withoutBinding(
  state: VaultState,
  binding: BindingRecord,
  removeApprovals: boolean,
): VaultState {
  return {
    ...state,
    localBindings: state.localBindings.filter(
      (entry) =>
        entry.projectId !== binding.projectId ||
        entry.root !== binding.root ||
        entry.device !== binding.device ||
        entry.inode !== binding.inode ||
        entry.checkoutId !== binding.checkoutId,
    ),
    profileApprovals: removeApprovals
      ? state.profileApprovals.filter(
          (approval) => !belongsTo(approval, binding),
        )
      : state.profileApprovals,
  };
}

// What unregister removes and shows: the binding this checkout matches (or, if
// it has none, the first legacy one), every legacy binding of that same project
// at this directory, and the approvals belonging to them. The fingerprint names
// each of those records, so a set that changed between the question and the
// write is detected.
function removalSet(state: VaultState, checkout: CheckoutIdentity) {
  const matched = findBinding(state, checkout);
  const legacy = legacyBindingsAt(state, checkout);
  const binding = matched ?? legacy[0];
  if (binding === undefined) return undefined;
  const removing = [
    ...(matched === undefined ? [] : [matched]),
    ...legacy.filter((entry) => entry.projectId === binding.projectId),
  ];
  const owned = state.profileApprovals.filter((approval) =>
    removing.some((entry) => belongsTo(approval, entry)),
  );
  const fingerprint = JSON.stringify([
    removing.map((entry) => [
      entry.projectId,
      entry.root,
      entry.device,
      entry.inode,
      entry.checkoutId ?? null,
    ]),
    owned.map((approval) => [
      approval.profile,
      approval.checkoutId ?? null,
      approval.approvedAt,
    ]),
  ]);
  return { binding, removing, approvals: owned.length, fingerprint };
}

export async function runUnregister(
  options: UnregisterOptions,
): Promise<UnregisterResult> {
  // Asked on a terminal or not at all, and before the vault is touched, so a
  // non-interactive caller learns it cannot act without a key prompt.
  if (!options.approver.available())
    throw new WardError("unregister_requires_terminal");
  const header = options.store.header();
  if (header === undefined) throw new WardError("vault_not_found");
  const key = await options.keyProvider.load(header.vaultId);
  try {
    const snapshot = options.store.read(key);
    let state: VaultState;
    try {
      state = parseVaultState(snapshot.plaintext);
    } finally {
      snapshot.plaintext.fill(0);
    }
    // The binding this checkout matches, and also any 0.1.1 binding of the same
    // project at the same directory, which matches nothing but can still be
    // cleared here (DEC-255 a7). Removal only: neither grants anything. A legacy
    // binding of another project at this directory is not touched and not
    // counted: the developer is shown one project, and only that one goes.
    const shown = removalSet(state, options.checkout);
    if (shown === undefined) throw new WardError("project_not_registered");
    const { binding, approvals } = shown;

    const first = options.approver.ask({
      kind: "binding",
      projectId: binding.projectId,
      root: binding.root,
      approvals,
    });
    if (first === "unavailable")
      throw new WardError("unregister_requires_terminal");
    if (first === "declined")
      return {
        kind: "unregister.result",
        data: {
          projectId: binding.projectId,
          status: "declined",
          binding: "kept",
          approvals: "kept",
        },
        text: [
          "Not unregistered.",
          "",
          "This checkout stays registered, and its approvals are untouched.",
        ].join("\n"),
      };

    let removeApprovals = false;
    if (approvals > 0) {
      const second = options.approver.ask({
        kind: "approvals",
        projectId: binding.projectId,
        root: binding.root,
        approvals,
      });
      if (second === "unavailable")
        throw new WardError("unregister_requires_terminal");
      removeApprovals = second === "approved";
    }

    let removedApprovals = 0;
    options.store.mutate(key, (plaintext) => {
      // The decision, repeated inside the transaction: what is removed must be
      // exactly what the developer was shown, bindings and approvals both, or
      // nothing is removed. A binding or approval that appeared since is not
      // consent given. The refusal is binding_changed (DEC-255 a9), not
      // project_not_registered, which is for a checkout with no binding at all.
      const current = parseVaultState(plaintext);
      const present = removalSet(current, options.checkout);
      if (
        present === undefined ||
        present.binding.projectId !== binding.projectId ||
        present.fingerprint !== shown.fingerprint
      )
        throw new WardError("binding_changed");
      removedApprovals = removeApprovals ? present.approvals : 0;
      return serializeVaultState(
        present.removing.reduce(
          (next, entry) => withoutBinding(next, entry, removeApprovals),
          current,
        ),
      );
    });
    const kept = approvals > 0 && !removeApprovals;
    return {
      kind: "unregister.result",
      data: {
        projectId: binding.projectId,
        status: "unregistered",
        binding: "removed",
        approvals:
          approvals === 0 ? "none" : removeApprovals ? "removed" : "kept",
        approvalsRemoved: removedApprovals,
      },
      text: [
        "Checkout unregistered.",
        "",
        `  project:   ${binding.projectId}`,
        "",
        "This checkout no longer has access to the project's secrets, and",
        "`ward run` from it is refused until it is registered again.",
        ...(kept
          ? [
              "",
              "Its profile approvals were kept. Registering this same clone again",
              "makes the ones this version wrote live until they expire or are",
              "revoked; an approval written by an earlier version never does.",
            ]
          : []),
        "Unregistering revokes nothing at a credential's provider.",
      ].join("\n"),
    };
  } finally {
    key.fill(0);
  }
}
