// `ward unregister`: withdraw this checkout's access (DEC-217 Q4, docs/adr/0022).
//
// Registration is how a checkout gains a project's secrets; this is the other
// half, the developer's way to take it back. It is interactive and narrow: it
// removes the binding for the directory it is run in — matched by path, device
// and inode, exactly as a binding is matched everywhere — and never another
// root's binding, whatever project it names. Its approvals are matched the same
// way plus the project. Removing the binding is one
// confirmation. Removing that binding's profile approvals is a second one,
// asked only when there are some, and declining it keeps them.
//
// What declining leaves behind is stated rather than hidden: an approval is
// bound to a directory's identity, so registering the same directory again
// revives an approval that was kept. A developer who wants the directory to
// start clean answers yes to both.
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
    // The binding this checkout matches, and also any 0.1.1 binding at the
    // same directory, which matches nothing but can still be cleared here
    // (DEC-255 a7). Removal only: neither grants anything.
    const matched = findBinding(state, options.checkout);
    const legacy = legacyBindingsAt(state, options.checkout);
    const binding = matched ?? legacy[0];
    if (binding === undefined) throw new WardError("project_not_registered");
    const removing = matched === undefined ? legacy : [matched, ...legacy];
    const approvals = state.profileApprovals.filter((approval) =>
      removing.some((entry) => belongsTo(approval, entry)),
    ).length;

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

    options.store.mutate(key, (plaintext) => {
      // The decision, repeated inside the transaction: the binding must still
      // be the one the developer was shown, or nothing is removed.
      const current = parseVaultState(plaintext);
      const present = findBinding(current, options.checkout);
      const presentLegacy = legacyBindingsAt(current, options.checkout);
      const subject = present ?? presentLegacy[0];
      if (subject === undefined || subject.projectId !== binding.projectId)
        throw new WardError("project_not_registered");
      return serializeVaultState(
        (present === undefined
          ? presentLegacy
          : [present, ...presentLegacy]
        ).reduce(
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
        approvalsRemoved: removeApprovals ? approvals : 0,
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
              "Its profile approvals were kept. Registering this same directory",
              "again makes them live until they expire or are revoked.",
            ]
          : []),
        "Unregistering revokes nothing at a credential's provider.",
      ].join("\n"),
    };
  } finally {
    key.fill(0);
  }
}
