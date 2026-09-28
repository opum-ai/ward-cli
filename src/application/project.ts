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

export interface InitResult {
  readonly projectId: string;
  readonly root: string;
  readonly manifest: "created" | "present";
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
}): "registered" | "already-registered" {
  const { store, key, projectId, checkout, registeredAt } = options;
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
  // being written, and the manifest must never land in the vault directory
  // (they coincide when the repository root is the home directory).
  if (isWithin(options.vaultDirectory, checkout.root))
    throw new WardError("project_path_unsafe");

  const stored = files.read("manifest");
  let manifest: ProjectManifest;
  let manifestStatus: "created" | "present";
  if (stored === undefined) {
    const projectId = options.newProjectId();
    if (!isOpaqueId(projectId)) throw new WardError("uncaught");
    manifest = newProjectManifest(projectId);
    files.write("manifest", serializeProjectManifest(manifest));
    manifestStatus = "created";
  } else {
    manifest = parseProjectManifest(stored);
    manifestStatus = "present";
  }

  const bridges: BridgeOutcome[] = [];
  for (const target of targets) {
    const document: ProjectDocument = agentTargetDocuments[target];
    const current = files.read(document);
    const update = upsertManagedBlock(current ?? "", wardBlockBody);
    if (update.status !== "unchanged") files.write(document, update.text);
    bridges.push({
      target,
      document: projectDocumentPaths[document],
      status: update.status,
    });
  }

  let registration: RegistrationOutcome = "skipped";
  if (options.register) {
    const header = options.store.header();
    if (header === undefined) throw new WardError("vault_not_found");
    if (!options.approver.available())
      throw new WardError("binding_requires_terminal");

    const key = await options.keyProvider.load(header.vaultId);
    try {
      const snapshot = options.store.read(key);
      const stored = findBinding(stateOf(snapshot.plaintext), checkout);
      // A binding at this exact directory is either this project's — a
      // repeat run, answered without asking anything — or another
      // project's, which is a conflict rather than a silent rebind.
      if (stored !== undefined && stored.projectId !== manifest.projectId)
        throw new WardError("binding_conflict");
      if (stored !== undefined) {
        registration = "already-registered";
      } else {
        const answer = options.approver.ask({
          projectId: manifest.projectId,
          root: checkout.root,
        });
        if (answer === "unavailable")
          throw new WardError("binding_requires_terminal");
        registration =
          answer === "approved"
            ? registerForProject({
                store: options.store,
                key,
                projectId: manifest.projectId,
                checkout,
                registeredAt: options.now().toISOString(),
              })
            : "declined";
      }
    } finally {
      key.fill(0);
    }
  }

  const lines = [
    "Ward project initialized.",
    "",
    `  project:  ${manifest.projectId}`,
    `  checkout: ${checkout.root}`,
    `  manifest: ${projectDocumentPaths.manifest} (${manifestStatus})`,
    ...bridges.map(
      (bridge) =>
        `  ${`${bridge.target}:`.padEnd(10)}${bridge.document} (${bridge.status})`,
    ),
    "",
    registrationText(registration),
    ...(bridges.length === 0
      ? [
          "",
          "Add Ward's guidance block to CLAUDE.md and AGENTS.md: `ward init --claude --codex`.",
        ]
      : []),
  ];

  return {
    projectId: manifest.projectId,
    root: checkout.root,
    manifest: manifestStatus,
    bridges,
    registration,
    text: lines.join("\n"),
  };
}
