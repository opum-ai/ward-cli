// `ward init` and the checkout-to-project resolution every later command
// builds on (spec §7.1, §8, §11.2).
//
// The rule this file implements: the tracked manifest names a project, and
// the encrypted vault binds that project to a canonical worktree root. The
// manifest is a claim; the binding is the authority. A checkout whose
// directory identity does not match a stored binding is unregistered, and
// nothing here falls back to another path, another project, or a parent
// directory — a copied manifest, a nested repository, a worktree, a moved
// path and a fresh clone at the same path are all simply unregistered, and
// each needs its own explicit registration.
//
// P0 limits, stated rather than implied: these are pathname and directory
// checks inside one OS account. They are guardrails against accident, not a
// boundary against a process running as the same user (spec §4.2, §7.1), and
// the interactive registration below is a mistake-reducer, not proof of a
// person (spec §4.3).
import { WardError } from "../contract/errors.ts";
import type { AgentTarget } from "../contract/manifest.ts";
import { isOpaqueId } from "../domain/identifiers.ts";
import { upsertManagedBlock } from "../domain/managed-block.ts";
import {
  newProjectManifest,
  type ProjectManifest,
  parseProjectManifest,
  serializeProjectManifest,
} from "../domain/project-manifest.ts";
import {
  type BindingRecord,
  type CheckoutIdentity,
  findBinding,
  parseVaultState,
  registerCheckout,
  serializeVaultState,
  type VaultState,
} from "../domain/vault-state.ts";
import type { RegistrationApprover } from "./approvals.ts";
import { agentTargetDocuments, wardBlockBody } from "./bridges.ts";
import type { KeyProvider } from "./key-provider.ts";
import {
  type ProjectDocument,
  type ProjectFiles,
  projectDocumentPaths,
} from "./project-files.ts";
import type { VaultStore } from "./vault-store.ts";

export interface Checkout {
  readonly identity: CheckoutIdentity;
  // Absent when this checkout has no manifest yet: an uninitialized
  // repository, which is not the same as an unregistered one.
  readonly manifest: ProjectManifest | undefined;
}

// Reads the manifest from the resolved root. Discovery is anchored here and
// never walks up: a nested repository has its own root, so it cannot reach a
// parent's manifest even when the parent is registered.
export function readCheckout(
  identity: CheckoutIdentity,
  files: ProjectFiles,
): Checkout {
  const text = files.read("manifest");
  return {
    identity,
    manifest: text === undefined ? undefined : parseProjectManifest(text),
  };
}

export function bindingFor(
  state: VaultState,
  checkout: Checkout,
): BindingRecord | undefined {
  return findBinding(state, checkout.identity);
}

export type RegistrationOutcome =
  | "registered"
  | "already-registered"
  | "declined"
  | "skipped";

export interface BridgeOutcome {
  readonly target: AgentTarget;
  readonly document: string;
  readonly status: "created" | "updated" | "unchanged";
}

// "restored" is a bound checkout whose manifest was missing: the vault's
// binding is the authority, so its project id is written back rather than a
// fresh one being minted beside it.
export type ManifestStatus = "created" | "present" | "restored";

export interface InitResult {
  readonly projectId: string;
  readonly root: string;
  readonly manifest: ManifestStatus;
  readonly bridges: readonly BridgeOutcome[];
  readonly registration: RegistrationOutcome;
  readonly text: string;
}

export interface InitOptions {
  readonly checkout: CheckoutIdentity;
  readonly files: ProjectFiles;
  readonly store: VaultStore;
  readonly keyProvider: KeyProvider;
  readonly approver: RegistrationApprover;
  // Where the user vault lives, so a repository that would contain it is
  // refused instead of being initialized around it (spec §6.1).
  readonly vaultDirectory: string;
  // Gives the checkout its identity nonce, creating it in the clone's git
  // directory when there is none (DEC-255 a2 clause 4). Called only once the
  // registration has been approved, so a declined or skipped registration
  // writes nothing into the repository's git directory.
  readonly bindCheckout: (checkout: CheckoutIdentity) => CheckoutIdentity;
  readonly register: boolean;
  readonly targets: readonly AgentTarget[];
  readonly now: () => Date;
  readonly newProjectId: () => string;
}

function isWithin(candidate: string, parent: string): boolean {
  return (
    candidate === parent ||
    candidate.startsWith(parent.endsWith("/") ? parent : `${parent}/`)
  );
}

// Marks the state that a concurrent run registered the checkout between this
// run's read and its write. It never escapes: store.mutate rolls the
// transaction back and rethrows it, and registerForProject turns it into the
// same answer the earlier read would have given.
class AlreadyRegistered extends Error {}

function stateOf(plaintext: Uint8Array) {
  try {
    return parseVaultState(plaintext);
  } finally {
    plaintext.fill(0);
  }
}

// Decides and writes in one place. The read before it answers the common
// case without writing; the decision is repeated inside the transaction, so
// two concurrent registrations cannot both write and neither can overwrite
// the other's binding.
function registerForProject(options: {
  store: VaultStore;
  key: Uint8Array;
  projectId: string;
  checkout: CheckoutIdentity;
  registeredAt: string;
  bindCheckout: (checkout: CheckoutIdentity) => CheckoutIdentity;
}): "registered" | "already-registered" {
  const { store, key, projectId, registeredAt } = options;
  const checkout = options.bindCheckout(options.checkout);
  const stored = store.read(key);
  const existing = findBinding(stateOf(stored.plaintext), checkout);
  if (existing !== undefined && existing.projectId !== projectId)
    throw new WardError("binding_conflict");
  if (existing !== undefined) return "already-registered";

  try {
    store.mutate(key, (plaintext) => {
      const state = stateOf(plaintext);
      const found = findBinding(state, checkout);
      if (found !== undefined && found.projectId !== projectId)
        throw new WardError("binding_conflict");
      if (found !== undefined) throw new AlreadyRegistered();
      return serializeVaultState(
        registerCheckout({ state, projectId, checkout, registeredAt }),
      );
    });
  } catch (error) {
    if (error instanceof AlreadyRegistered) return "already-registered";
    throw error;
  }
  return "registered";
}

function registrationText(outcome: RegistrationOutcome): string {
  switch (outcome) {
    case "registered":
      return "Registered this checkout with Ward. This project's secrets can now be used from it.";
    case "already-registered":
      return "This checkout was already registered with Ward.";
    case "declined":
      return "Not registered: the registration prompt was answered no. Run `ward init` again in a terminal when you want it.";
    case "skipped":
      return "Not registered (--no-register). The project files are ready, and this checkout has no access to the project's secrets until a developer registers it.";
  }
}

export async function initProject(options: InitOptions): Promise<InitResult> {
  const { checkout, files, targets } = options;

  // The user vault must never live inside the repository whose manifest is
  // being written, the manifest must never land in the vault directory (they
  // coincide when the repository root is the home directory), and a
  // repository rooted inside the vault directory is refused from the other
  // side of the same rule.
  if (
    isWithin(options.vaultDirectory, checkout.root) ||
    isWithin(checkout.root, options.vaultDirectory)
  )
    throw new WardError("project_path_unsafe");

  const stored = files.read("manifest");
  const existing =
    stored === undefined ? undefined : parseProjectManifest(stored);

  const freshManifest = (): ProjectManifest => {
    const projectId = options.newProjectId();
    if (!isOpaqueId(projectId)) throw new WardError("uncaught");
    return newProjectManifest(projectId);
  };

  // Decides every write before making any of them: the manifest and every
  // bridge target are read and transformed first, and only then written in
  // that order. A conflict therefore changes nothing — a malformed marker in
  // the second target must not leave the first target, or the manifest,
  // already rewritten.
  const prepare = (
    write: { manifest: ProjectManifest; status: ManifestStatus } | undefined,
  ): {
    manifest: ProjectManifest;
    status: ManifestStatus;
    bridges: BridgeOutcome[];
  } => {
    const manifest = write?.manifest ?? existing;
    if (manifest === undefined) throw new WardError("uncaught");
    const planned = targets.map((target) => {
      const document: ProjectDocument = agentTargetDocuments[target];
      const current = files.read(document);
      const update = upsertManagedBlock(current ?? "", wardBlockBody);
      return { target, document, status: update.status, text: update.text };
    });
    if (write !== undefined)
      files.write("manifest", serializeProjectManifest(write.manifest));
    for (const plan of planned)
      if (plan.status !== "unchanged") files.write(plan.document, plan.text);
    return {
      manifest,
      status: write?.status ?? "present",
      bridges: planned.map((plan) => ({
        target: plan.target,
        document: projectDocumentPaths[plan.document],
        status: plan.status,
      })),
    };
  };

  let prepared: {
    manifest: ProjectManifest;
    status: ManifestStatus;
    bridges: BridgeOutcome[];
  };
  let registration: RegistrationOutcome = "skipped";
  let binding: BindingRecord | undefined;

  if (!options.register) {
    prepared = prepare(
      existing === undefined
        ? { manifest: freshManifest(), status: "created" }
        : undefined,
    );
  } else {
    const header = options.store.header();
    if (header === undefined) {
      // No vault exists, so no binding can exist for this checkout either:
      // the files are prepared and setup is named, as before.
      prepare(
        existing === undefined
          ? { manifest: freshManifest(), status: "created" }
          : undefined,
      );
      throw new WardError("vault_not_found");
    }
    if (!options.approver.available()) {
      // Refused before the vault key is read, so this path cannot consult
      // the binding: it prepares the files without authority, and a later
      // interactive run reconciles them.
      prepare(
        existing === undefined
          ? { manifest: freshManifest(), status: "created" }
          : undefined,
      );
      throw new WardError("binding_requires_terminal");
    }

    const key = await options.keyProvider.load(header.vaultId);
    try {
      const snapshot = options.store.read(key);
      binding = findBinding(stateOf(snapshot.plaintext), checkout);
      if (binding !== undefined) {
        // A binding at this exact directory is either this project's — a
        // repeat run, answered without asking anything — or another
        // project's, which is a conflict rather than a silent rebind. The
        // decision is taken before any repository write, and a bound
        // checkout whose manifest is missing is restored from the vault:
        // minting a fresh id there would leave the manifest and the binding
        // permanently disagreeing.
        if (existing !== undefined && existing.projectId !== binding.projectId)
          throw new WardError("binding_conflict");
        prepared = prepare(
          existing === undefined
            ? {
                manifest: newProjectManifest(binding.projectId),
                status: "restored",
              }
            : undefined,
        );
        registration = "already-registered";
      } else {
        prepared = prepare(
          existing === undefined
            ? { manifest: freshManifest(), status: "created" }
            : undefined,
        );
        const answer = options.approver.ask({
          projectId: prepared.manifest.projectId,
          root: checkout.root,
        });
        if (answer === "unavailable")
          throw new WardError("binding_requires_terminal");
        registration =
          answer === "approved"
            ? registerForProject({
                store: options.store,
                key,
                projectId: prepared.manifest.projectId,
                checkout,
                registeredAt: options.now().toISOString(),
                bindCheckout: options.bindCheckout,
              })
            : "declined";
      }
    } finally {
      key.fill(0);
    }

    // The manifest was read before the prompt and written before it too, and
    // a concurrent run — the documented `--no-register` beside an
    // interactive one — can replace it in between. A manifest that no longer
    // names the project this run bound the checkout to is reported rather
    // than answered as a success; nothing is written here, and the next run
    // reconciles the checkout.
    const settled =
      binding?.projectId ??
      (registration === "registered" || registration === "already-registered"
        ? prepared.manifest.projectId
        : undefined);
    if (settled !== undefined) {
      const current = files.read("manifest");
      if (
        current !== undefined &&
        parseProjectManifest(current).projectId !== settled
      )
        throw new WardError("binding_conflict");
    }
  }

  const lines = [
    "Ward project initialized.",
    "",
    `  project:  ${prepared.manifest.projectId}`,
    `  checkout: ${checkout.root}`,
    `  manifest: ${projectDocumentPaths.manifest} (${prepared.status})`,
    ...prepared.bridges.map(
      (bridge) =>
        `  ${`${bridge.target}:`.padEnd(10)}${bridge.document} (${bridge.status})`,
    ),
    "",
    registrationText(registration),
    ...(prepared.status === "restored"
      ? [
          "",
          "The manifest was missing, so its project id was written back from the vault's binding for this checkout.",
        ]
      : []),
    ...(prepared.bridges.length === 0
      ? [
          "",
          "Add Ward's guidance block to CLAUDE.md and AGENTS.md: `ward init --claude --codex`.",
        ]
      : []),
  ];

  return {
    projectId: prepared.manifest.projectId,
    root: checkout.root,
    manifest: prepared.status,
    bridges: prepared.bridges,
    registration,
    text: lines.join("\n"),
  };
}
