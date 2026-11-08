// `ward profile` and `ward check`: the developer's approval of an HTTPS
// profile, and whether this checkout is ready to run one (spec §9.1-9.2, §8,
// docs/adr/0003).
//
// The rule this file implements: a manifest is a request, not authority. A
// developer approves a normalized operation for one binding, and from then on
// the declared profile must match that snapshot exactly — a changed
// destination, method, authentication reference, body or output policy
// invalidates the approval, an unknown field refuses it, and there is no
// runtime override of any of them. Nothing here reaches the network:
// readiness is answered from the vault and the manifest alone, and the
// transport that would send a request does not exist in this build (WCLI-10).
//
// Prompts print values; results never do. A developer has to read the
// operation to approve it, so the question carries it to the terminal. A
// result carries state — a status, a field name, a boolean — so a URL or a
// header value cannot reach a transcript through stdout, the same line
// `ward secret` draws between an alias and a value.
import {
  type ExitCode,
  exitCodes,
  type ResultKind,
} from "../contract/envelope.ts";
import { WardError } from "../contract/errors.ts";
import { isSignKey } from "../domain/secret.ts";
import {
  defaultApprovalTtlMs,
  parseApprovalTtl,
} from "../domain/approval-ttl.ts";
import { escapeForDisplay } from "../domain/display.ts";
import {
  type ApprovedSnapshot,
  approvedSnapshotsMatch,
  differingApprovedFields,
  isProfileName,
  isSignSnapshot,
  normalizeDeclaration,
  withSignKeyId,
  type ProfileSnapshotField,
  snapshotVersionFor,
} from "../domain/profile.ts";
import {
  type ProjectManifest,
  parseProjectManifest,
} from "../domain/project-manifest.ts";
import {
  approvalExpired,
  type CheckoutIdentity,
  findProfileApproval,
  findSecret,
  resolveSecret,
  type ProfileApprovalRecord,
  parseVaultState,
  serializeVaultState,
  type VaultState,
  withoutProfileApproval,
  withProfileApproval,
} from "../domain/vault-state.ts";
import type { ProfileApprover } from "./approvals.ts";
import {
  type BindingAuthority,
  bindingAuthority,
  boundProject,
  requireBinding,
  requireManifest,
} from "./binding.ts";
import type { KeyProvider } from "./key-provider.ts";
import { type Checkout, readCheckout } from "./project.ts";
import type { ProjectFiles } from "./project-files.ts";
import type { VaultStore } from "./vault-store.ts";

export interface ProfileOptions {
  readonly checkout: CheckoutIdentity;
  readonly files: ProjectFiles;
  readonly store: VaultStore;
  readonly keyProvider: KeyProvider;
  readonly approver: ProfileApprover;
  readonly now: () => Date;
}

export interface CheckOptions {
  readonly now: () => Date;
  readonly checkout: CheckoutIdentity;
  readonly files: ProjectFiles;
  readonly store: VaultStore;
  readonly keyProvider: KeyProvider;
}

export interface ProfileCommandInput {
  readonly action: string;
  readonly profile: string | undefined;
  // `--ttl` on approve: the approval's lifetime, as typed.
  readonly ttl?: string | undefined;
}

export interface CheckCommandInput {
  readonly profile: string | undefined;
}

export interface ProfileResult {
  readonly kind: ResultKind;
  readonly data: Record<string, unknown>;
  readonly text: string;
}

export interface CheckResult {
  readonly kind: ResultKind;
  readonly data: Record<string, unknown>;
  readonly text: string;
  // 6 when the checkout is not ready, the same finding code `ward doctor`
  // uses: a check that answered "no" is not an internal failure.
  readonly exitCode?: ExitCode;
}

// The states a profile can be in, per item. They are named rather than
// collapsed into one word so that `ward profile list` can report an
// inventory and `ward check` can report what is missing, from one
// evaluation.
export type DeclarationState = "valid" | "invalid";
export type ApprovalState =
  | "approved"
  | "missing"
  | "stale"
  | "expired"
  | "not-evaluated";
export type SecretState =
  | "present"
  | "missing"
  | "revoked"
  // The alias names a signing key, which is never a credential (DEC-262 (2)).
  // Reported, not thrown: one such declaration must not take down the report
  // for every other profile.
  | "sign-key"
  // A sign profile's key alias: no record at all, or an ordinary secret
  // holding the alias. They need different advice, since `ward key generate`
  // refuses an alias an ordinary secret already holds.
  | "sign-key-missing"
  | "sign-key-alias-taken"
  | "not-evaluated";

export interface ProfileReadiness {
  readonly profile: string;
  readonly declaration: DeclarationState;
  readonly approval: ApprovalState;
  readonly secret: SecretState;
  // Which fields of the snapshot the declaration no longer matches. Field
  // names only, so no caller has to decide whether a value is safe to echo.
  readonly differing: readonly ProfileSnapshotField[];
}

// The closed vocabulary `ward check` reports. An agent renders these; a new
// item — a cross-project grant, once WCLI-12 lands — is an addition here
// rather than a shape change.
export const profileCheckReasons = [
  "binding",
  "declaration",
  "approval",
  "approval-stale",
  "approval-expired",
  "secret",
  "grant-revoked",
  "sign-key",
  "sign-key-missing",
  "sign-key-alias-taken",
] as const;

export type ProfileCheckReason = (typeof profileCheckReasons)[number];

interface ReadinessReport {
  readonly projectId: string;
  readonly root: string;
  readonly binding: "registered" | "missing";
  readonly ready: boolean;
  readonly profiles: readonly ProfileReadiness[];
}

interface OpenedVault {
  readonly checkout: Checkout;
  readonly key: Uint8Array;
  readonly state: VaultState;
}

// The vault, the key and the parsed state. The key is zeroed on every path
// out and the read's plaintext as soon as it has been parsed. No binding is
// required here: `ward check` reports a missing binding rather than
// refusing, which is the one place this differs from `ward secret`.
async function withOpenVault<T>(
  options: { files: ProjectFiles; store: VaultStore; keyProvider: KeyProvider },
  identity: CheckoutIdentity,
  run: (opened: OpenedVault) => T | Promise<T>,
): Promise<T> {
  const checkout = readCheckout(identity, options.files);
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
    return await run({ checkout, key, state });
  } finally {
    key.fill(0);
  }
}

// One profile's readiness, from the manifest and the vault alone. A
// declaration Ward refuses — or a name it cannot address — is reported as an
// invalid declaration rather than thrown: the other profiles in the same
// manifest are still answerable, and a broken one must not hide them.
function readinessFor(options: {
  now: Date;
  name: string;
  manifest: ProjectManifest;
  state: VaultState;
  identity: CheckoutIdentity;
  authority: BindingAuthority;
}): ProfileReadiness {
  const { name, manifest, state, identity, authority } = options;
  const declared = Object.hasOwn(manifest.profiles, name)
    ? manifest.profiles[name]
    : undefined;
  let declaration: DeclarationState = "valid";
  let snapshot: ApprovedSnapshot | undefined;
  if (!isProfileName(name)) declaration = "invalid";
  else {
    try {
      snapshot = normalizeDeclaration(declared);
    } catch {
      declaration = "invalid";
    }
  }

  // Without a binding there is no checkout to hold an approval and no
  // authority to read this project's records, so neither is evaluated. The
  // declaration is answered either way: it is a fact about the manifest.
  if (authority.kind === "unbound" || snapshot === undefined)
    return {
      profile: name,
      declaration,
      approval: "not-evaluated",
      secret: "not-evaluated",
      differing: [],
    };
  // A sign approval binds the key's id (DEC-262 a8), so the declaration is
  // compared as it stands now: against the key the alias resolves to today.
  if (isSignSnapshot(snapshot)) {
    const current = findSecret(state, authority.projectId, snapshot.key);
    snapshot = withSignKeyId(
      snapshot,
      current !== undefined && isSignKey(current) ? current.id : undefined,
    );
  }

  const approved = findProfileApproval(
    state,
    identity,
    authority.projectId,
    name,
  );
  const differing =
    approved === undefined
      ? []
      : differingApprovedFields(snapshot, approved.snapshot);
  // A changed declaration is stale whatever the clock says; an unchanged one
  // is expired once its lifetime has run out (DEC-217 Q5).
  const approval: ApprovalState =
    approved === undefined
      ? "missing"
      : differing.length > 0
        ? "stale"
        : approvalExpired(approved, options.now)
          ? "expired"
          : "approved";
  // A revoked grant is its own state and not "missing": the advice for a
  // missing credential is to store one, and storing a local secret under a
  // revoked grant's alias would block the owner from granting it again.
  let secret: SecretState;
  if (isSignSnapshot(snapshot)) {
    // A sign profile's credential is a signing key this project owns. A key is
    // never granted (DEC-262 (2)), and an ordinary secret under the alias is
    // not a signing key, so both read as missing.
    const key = findSecret(state, authority.projectId, snapshot.key);
    secret =
      key === undefined
        ? "sign-key-missing"
        : isSignKey(key)
          ? "present"
          : "sign-key-alias-taken";
  } else {
    const resolution = resolveSecret(
      state,
      authority.projectId,
      snapshot.auth.secret,
    );
    const resolved = resolution.kind;
    const usable = resolved === "owned" || resolved === "granted";
    secret =
      usable && isSignKey(resolution.secret)
        ? "sign-key"
        : usable
          ? "present"
          : resolved === "revoked"
            ? "revoked"
            : "missing";
  }
  return {
    profile: name,
    declaration,
    approval,
    secret,
    differing,
  };
}

// The profile names to report: everything declared, in a stable order, or
// exactly one name the manifest declares. A name that is not declared is a
// not-found rather than an empty answer.
function selectedProfiles(
  manifest: ProjectManifest,
  profile: string | undefined,
): readonly string[] {
  const declared = Object.keys(manifest.profiles).sort();
  if (profile === undefined) return declared;
  if (!isProfileName(profile)) throw new WardError("profile_name_invalid");
  if (!Object.hasOwn(manifest.profiles, profile))
    throw new WardError("profile_not_found");
  return [profile];
}

function readinessReport(options: {
  now: Date;
  checkout: Checkout;
  state: VaultState;
  identity: CheckoutIdentity;
  profile: string | undefined;
}): ReadinessReport {
  const manifest = requireManifest(options.checkout);
  const authority = bindingAuthority(options.checkout, options.state);
  const profiles = selectedProfiles(manifest, options.profile).map((name) =>
    readinessFor({
      now: options.now,
      name,
      manifest,
      state: options.state,
      identity: options.identity,
      authority,
    }),
  );
  return {
    // The manifest's own id. Registered or not, it is what this checkout
    // claims, and it is not a credential (docs/adr/0003).
    projectId: manifest.projectId,
    root: options.identity.root,
    binding: authority.kind === "bound" ? "registered" : "missing",
    ready:
      authority.kind === "bound" &&
      profiles.every((entry) => checkReasons(entry, false).length === 0),
    profiles,
  };
}

// What one profile is missing, given whether this checkout is bound at all.
// `ward profile list` and `ward check` both derive from this, and `ready` is
// exactly "this came back empty".
function checkReasons(
  entry: ProfileReadiness,
  unbound: boolean,
): readonly ProfileCheckReason[] {
  const reasons: ProfileCheckReason[] = [];
  if (unbound) reasons.push("binding");
  if (entry.declaration === "invalid") reasons.push("declaration");
  if (entry.approval === "missing") reasons.push("approval");
  if (entry.approval === "stale") reasons.push("approval-stale");
  if (entry.approval === "expired") reasons.push("approval-expired");
  if (entry.secret === "missing") reasons.push("secret");
  if (entry.secret === "revoked") reasons.push("grant-revoked");
  if (entry.secret === "sign-key") reasons.push("sign-key");
  if (entry.secret === "sign-key-missing") reasons.push("sign-key-missing");
  if (entry.secret === "sign-key-alias-taken")
    reasons.push("sign-key-alias-taken");
  return reasons;
}

const reasonPhrases: Record<ProfileCheckReason, string> = {
  binding: "this checkout is not registered",
  declaration: "the declaration is not one Ward can use",
  approval: "no approval in this checkout",
  "approval-stale": "the declaration changed after approval",
  "approval-expired": "the approval has expired",
  secret: "the credential is not stored in this project",
  "grant-revoked":
    "the grant behind the credential was revoked, or its owner secret was deleted",
  "sign-key":
    "the credential alias names a signing key, which is never a credential",
  "sign-key-missing": "the signing key does not exist in this project",
  "sign-key-alias-taken":
    "an ordinary secret holds the signing key's alias in this project",
};

function reasonPhrase(
  entry: ProfileReadiness,
  reason: ProfileCheckReason,
): string {
  if (reason === "approval-stale" && entry.differing.length > 0)
    return `${reasonPhrases[reason]} (${entry.differing.join(", ")})`;
  return reasonPhrases[reason];
}

// What a developer would have to do about what is missing, named once per
// kind rather than once per profile.
function checkGuidance(report: ReadinessReport): readonly string[] {
  const unbound = report.binding !== "registered";
  const reasons = new Set(
    report.profiles.flatMap((entry) => checkReasons(entry, unbound)),
  );
  const guidance: string[] = [];
  if (reasons.has("binding"))
    guidance.push(
      "Register this checkout with `ward init` in a terminal to make its profiles usable.",
    );
  if (reasons.has("approval") || reasons.has("approval-stale"))
    guidance.push(
      "A developer approves a profile in a terminal with `ward profile approve <name>`.",
    );
  if (reasons.has("secret"))
    guidance.push(
      "A developer stores a missing credential in a terminal with `ward secret set <alias>`.",
    );
  if (reasons.has("grant-revoked"))
    guidance.push(
      "The owning project's developer grants the secret again with `ward secret grant`. Do not store a local secret under that alias: it would block the grant.",
    );
  if (reasons.has("sign-key"))
    guidance.push(
      "Name a different secret in the profile's auth.secret, or delete the signing key and store an ordinary secret under that alias with `ward secret set`.",
    );
  if (reasons.has("sign-key-missing"))
    guidance.push(
      "A developer creates a missing signing key in a terminal with `ward key generate <alias>`.",
    );
  if (reasons.has("sign-key-alias-taken"))
    guidance.push(
      "An ordinary secret holds the signing key's alias. Delete it with `ward secret delete <alias>`, then create the key with `ward key generate <alias>`, or name a different alias in the profile's key.",
    );
  if (reasons.has("declaration"))
    guidance.push(
      "Fix the profile's declaration in .ward/project.json; Ward refuses what it cannot read exactly.",
    );
  return guidance;
}

function checkText(report: ReadinessReport): string {
  // The heading says what is actually true. A registered checkout with no
  // declared profiles is ready (there is nothing to refuse), so "not ready"
  // with nothing declared can only be the missing binding — and saying a
  // profile would be refused there would be the one line of this report
  // contradicted by the line under it.
  const heading = report.ready
    ? "Ready: Ward can run every declared profile from this checkout."
    : report.profiles.length === 0
      ? "Not ready: this checkout is not registered with Ward."
      : "Not ready: Ward would refuse to run at least one declared profile.";
  const lines = [heading, ""];
  const unbound = report.binding !== "registered";
  if (report.profiles.length === 0)
    lines.push("No profiles are declared in this project's manifest.");
  else
    for (const entry of report.profiles) {
      const reasons = checkReasons(entry, unbound);
      // A name comes from a tracked file anyone can edit, and a name the
      // profile grammar refuses is reported rather than dropped, so it is
      // escaped here for the same reason the approval prompt escapes the
      // operation: the value shown is read by a person, not by a parser.
      const shown = escapeForDisplay(entry.profile);
      lines.push(
        reasons.length === 0
          ? `  ${shown}: ready`
          : `  ${shown}: not ready (${reasons.map((reason) => reasonPhrase(entry, reason)).join(", ")})`,
      );
    }
  if (report.binding !== "registered") {
    lines.push("", "This checkout is not registered with Ward.");
  }
  const guidance = checkGuidance(report);
  if (guidance.length > 0) lines.push("", ...guidance);
  return lines.join("\n");
}

const approvalWords: Record<ApprovalState, string> = {
  approved: "approved",
  missing: "not approved",
  stale: "approval out of date",
  expired: "approval expired",
  "not-evaluated": "not evaluated",
};

function profileStateWord(
  entry: ProfileReadiness,
  binding: ReadinessReport["binding"],
): string {
  if (entry.declaration === "invalid") return "invalid declaration";
  if (binding !== "registered") return "not evaluated (not registered)";
  return approvalWords[entry.approval];
}

function listText(report: ReadinessReport): string {
  if (report.profiles.length === 0)
    return "No profiles are declared in this project's manifest.";
  // Escaped before the column is measured, so the escapes are what the
  // padding aligns — a name carrying terminal control bytes cannot widen or
  // misalign the column it is printed in.
  const names = report.profiles.map((entry) => escapeForDisplay(entry.profile));
  const width = Math.max(...names.map((name) => name.length));
  return [
    "Profiles declared in this project, and their approval state here.",
    "",
    ...report.profiles.map(
      (entry, index) =>
        `  ${(names[index] ?? "").padEnd(width)}  ${profileStateWord(entry, report.binding)}`,
    ),
    "",
    "A profile is runnable when it is approved here and its credential (a stored secret, or for a sign profile a signing key) exists.",
  ].join("\n");
}

// The write, with the authority decision repeated inside the transaction, so
// a change that raced another Ward process cannot act on a state the earlier
// read no longer describes.
function writeApproval(
  options: { store: VaultStore; checkout: CheckoutIdentity },
  key: Uint8Array,
  projectId: string,
  change: (state: VaultState) => VaultState,
): void {
  options.store.mutate(key, (plaintext) => {
    const state = parseVaultState(plaintext);
    requireBinding(state, options.checkout, projectId);
    return serializeVaultState(change(state));
  });
}

// Whether the manifest still normalizes to the snapshot that was displayed.
// The approval prompt is answered from one rendering of the manifest, and
// this is the check that the file has not moved since.
function stillApproved(
  options: ProfileOptions,
  projectId: string,
  name: string,
  snapshot: ApprovedSnapshot,
): boolean {
  const text = options.files.read("manifest");
  if (text === undefined) return false;
  try {
    const manifest = parseProjectManifest(text);
    if (manifest.projectId !== projectId) return false;
    if (!Object.hasOwn(manifest.profiles, name)) return false;
    return approvedSnapshotsMatch(
      withSignKeyId(
        normalizeDeclaration(manifest.profiles[name]),
        isSignSnapshot(snapshot) ? snapshot.keyId : undefined,
      ),
      snapshot,
    );
  } catch {
    return false;
  }
}

async function approveProfile(
  name: string,
  opened: OpenedVault,
  projectId: string,
  options: ProfileOptions,
  ttlMs: number,
): Promise<ProfileResult> {
  const manifest = requireManifest(opened.checkout);
  if (!Object.hasOwn(manifest.profiles, name))
    throw new WardError("profile_not_found");
  let snapshot = normalizeDeclaration(manifest.profiles[name]);
  if (isSignSnapshot(snapshot)) {
    // The approval is of this key, by id (DEC-262 a8). With no key under the
    // alias there is nothing to bind, so nothing is asked.
    const key = findSecret(opened.state, projectId, snapshot.key);
    if (key === undefined || !isSignKey(key))
      throw new WardError("sign_key_not_found");
    snapshot = withSignKeyId(snapshot, key.id);
  }
  if (!options.approver.available())
    throw new WardError("profile_requires_terminal");
  const answer = options.approver.ask({
    kind: "approve",
    profile: name,
    projectId,
    root: options.checkout.root,
    snapshot,
  });
  if (answer === "declined")
    return {
      kind: "profile.approve",
      data: { profile: name, projectId, status: "declined" },
      text: [
        "Not approved.",
        "",
        `  profile:  ${name}`,
        "",
        "The profile is left unapproved, and Ward will not run it from this",
        "checkout.",
      ].join("\n"),
    };
  // A terminal that vanished mid-question did not answer yes.
  if (answer !== "approved") throw new WardError("profile_requires_terminal");
  if (!stillApproved(options, projectId, name, snapshot))
    throw new WardError("profile_changed");
  const approvedNow = options.now();
  const approvedAt = approvedNow.toISOString();
  const expiresAt = new Date(approvedNow.getTime() + ttlMs).toISOString();
  const record: ProfileApprovalRecord = {
    profile: name,
    projectId,
    root: options.checkout.root,
    device: options.checkout.device,
    inode: options.checkout.inode,
    ...(options.checkout.checkoutId === undefined
      ? {}
      : { checkoutId: options.checkout.checkoutId }),
    approvedAt,
    expiresAt,
    // Written with the record so a later build reads the snapshot under the
    // rules that produced it rather than under its own (spec §6.2).
    snapshotVersion: snapshotVersionFor(snapshot),
    snapshot,
  };
  writeApproval(options, opened.key, projectId, (state) => {
    // Inside the transaction: a key replaced while the question was open must
    // not be approved under the old key's id.
    if (isSignSnapshot(snapshot)) {
      const key = findSecret(state, projectId, snapshot.key);
      if (key === undefined || !isSignKey(key) || key.id !== snapshot.keyId)
        throw new WardError("profile_changed");
    }
    return withProfileApproval(state, record);
  });
  return {
    kind: "profile.approve",
    data: {
      profile: name,
      projectId,
      status: "approved",
      approvedAt,
      expiresAt,
    },
    text: [
      "Profile approved.",
      "",
      `  profile:   ${name}`,
      `  project:   ${projectId}`,
      // A path is the developer's own filesystem and can carry control or
      // format bytes, exactly as the prompt this was answered on assumes.
      `  checkout:  ${escapeForDisplay(options.checkout.root)}`,
      `  approved:  ${approvedAt}`,
      `  expires:   ${expiresAt}`,
      "",
      "Ward runs this operation only while the declared profile still matches",
      "what was approved, and only until the approval expires.",
      isSignSnapshot(snapshot)
        ? "A change to the key alias or the domain prefixes needs approval again, and so does an expired approval."
        : "A change to the destination, method, authentication reference, headers, body policy or output policy needs approval again, and so does an expired approval.",
    ].join("\n"),
  };
}

async function revokeProfile(
  name: string,
  opened: OpenedVault,
  projectId: string,
  options: ProfileOptions,
): Promise<ProfileResult> {
  if (
    findProfileApproval(opened.state, options.checkout, projectId, name) ===
    undefined
  )
    throw new WardError("profile_not_approved");
  if (!options.approver.available())
    throw new WardError("profile_requires_terminal");
  const answer = options.approver.ask({
    kind: "revoke",
    profile: name,
    projectId,
    root: options.checkout.root,
  });
  if (answer === "declined")
    return {
      kind: "profile.revoke",
      data: { profile: name, projectId, status: "declined" },
      text: [
        "Not revoked.",
        "",
        `  profile:  ${name}`,
        "",
        "The approval is left in place.",
      ].join("\n"),
    };
  if (answer !== "approved") throw new WardError("profile_requires_terminal");
  writeApproval(options, opened.key, projectId, (state) => {
    // Re-checked inside the transaction: another Ward process may have
    // revoked or replaced this approval since the read.
    if (
      findProfileApproval(state, options.checkout, projectId, name) ===
      undefined
    )
      throw new WardError("profile_not_approved");
    return withoutProfileApproval(state, options.checkout, projectId, name);
  });
  return {
    kind: "profile.revoke",
    data: { profile: name, projectId, status: "revoked" },
    text: [
      "Approval revoked.",
      "",
      `  profile:  ${name}`,
      `  project:  ${projectId}`,
      "",
      "Ward will not admit this profile from this checkout again until a",
      "developer approves it. This revokes nothing at the credential's",
      "provider, and it cannot recall a request Ward has already sent.",
    ].join("\n"),
  };
}

export const profileActions = ["list", "approve", "revoke"] as const;

type ProfileAction = (typeof profileActions)[number];

function isProfileAction(value: string): value is ProfileAction {
  return (profileActions as readonly string[]).includes(value);
}

function requireProfileName(profile: string | undefined): string {
  if (profile === undefined) throw new WardError("missing_argument");
  if (!isProfileName(profile)) throw new WardError("profile_name_invalid");
  return profile;
}

// `ward profile list|approve|revoke`. Listing needs no terminal and no
// authority beyond the checkout it is run in; approving and revoking are the
// developer's acts and need both a binding and a terminal to ask on.
export async function runProfile(
  input: ProfileCommandInput,
  options: ProfileOptions,
): Promise<ProfileResult> {
  const { action } = input;
  if (!isProfileAction(action)) throw new WardError("profile_action_unknown");
  if (input.ttl !== undefined && action !== "approve")
    throw new WardError("profile_option_unexpected");
  if (action === "list") {
    if (input.profile !== undefined) throw new WardError("unexpected_argument");
    return withOpenVault(options, options.checkout, ({ checkout, state }) => {
      const report = readinessReport({
        now: options.now(),
        checkout,
        state,
        identity: options.checkout,
        profile: undefined,
      });
      return {
        kind: "profile.list",
        data: {
          projectId: report.projectId,
          root: report.root,
          binding: report.binding,
          profiles: report.profiles.map((entry) => ({
            profile: entry.profile,
            declaration: entry.declaration,
            approval: entry.approval,
            secret: entry.secret,
          })),
        },
        text: listText(report),
      };
    });
  }
  const name = requireProfileName(input.profile);
  // Judged before the vault is opened, like the name: a lifetime Ward will
  // not record costs no key prompt.
  const ttlMs =
    input.ttl === undefined
      ? defaultApprovalTtlMs
      : parseApprovalTtl(input.ttl);
  if (ttlMs === undefined) throw new WardError("profile_ttl_invalid");
  return withOpenVault(options, options.checkout, async (opened) => {
    const projectId = boundProject(opened.checkout, opened.state);
    return action === "approve"
      ? await approveProfile(name, opened, projectId, options, ttlMs)
      : await revokeProfile(name, opened, projectId, options);
  });
}

// `ward check [profile]`: local readiness only. It reads the vault, the
// checkout binding and the manifest, asks the credential store for the
// vault key, and stops there — there is no transport port in this build, so
// a network call is not something this function could make even by mistake.
export async function runCheck(
  input: CheckCommandInput,
  options: CheckOptions,
): Promise<CheckResult> {
  return withOpenVault(options, options.checkout, ({ checkout, state }) => {
    const report = readinessReport({
      now: options.now(),
      checkout,
      state,
      identity: options.checkout,
      profile: input.profile,
    });
    const unbound = report.binding !== "registered";
    return {
      kind: "check.report",
      data: {
        projectId: report.projectId,
        root: report.root,
        binding: report.binding,
        ready: report.ready,
        profiles: report.profiles.map((entry) => {
          const reasons = checkReasons(entry, unbound);
          return {
            profile: entry.profile,
            ready: reasons.length === 0,
            reasons,
            differing: entry.differing,
          };
        }),
      },
      text: checkText(report),
      ...(report.ready ? {} : { exitCode: exitCodes.validation }),
    };
  });
}
