// The ports through which a developer answers Ward's interactive questions:
// whether to register this checkout for a project (spec §7.1), and whether to
// approve or revoke an HTTPS profile (spec §9.2, docs/adr/0003).
//
// Spec §4.3 is explicit about what an interactive gate is worth: it reduces
// mistakes, and it is not proof of human identity. So an outcome is
// three-valued rather than a boolean. "unavailable" means Ward had no
// interactive terminal to ask on, and is never treated as consent or as a
// refusal — a caller that cannot ask must not act (spec §7.1).
//
// Neither port carries a secret. An approval question carries the normalized
// operation — method, URL, header names and values, policies — which the
// manifest already holds in the repository, and the secret reference is an
// alias, never a value.
import type { NormalizedProfile } from "../domain/profile.ts";

export interface RegistrationRequest {
  readonly projectId: string;
  // The canonical worktree root being registered.
  readonly root: string;
}

export type RegistrationAnswer = "approved" | "declined" | "unavailable";

export interface RegistrationApprover {
  // Whether there is an interactive terminal to ask on at all. A caller
  // checks this before it reaches for the vault, so a non-interactive run
  // learns it cannot register without touching the credential store.
  available(): boolean;
  ask(request: RegistrationRequest): RegistrationAnswer;
}

export interface ProfileApprovalQuestion {
  readonly kind: "approve";
  readonly profile: string;
  readonly projectId: string;
  readonly root: string;
  // The normalized operation the developer is being asked to approve. It is
  // what gets stored if the answer is yes, so the question and the record
  // cannot describe different operations.
  readonly snapshot: NormalizedProfile;
}

export interface ProfileRevocationQuestion {
  readonly kind: "revoke";
  readonly profile: string;
  readonly projectId: string;
  readonly root: string;
}

export type ProfileQuestion =
  | ProfileApprovalQuestion
  | ProfileRevocationQuestion;

export type ProfileAnswer = "approved" | "declined" | "unavailable";

export interface ProfileApprover {
  available(): boolean;
  ask(question: ProfileQuestion): ProfileAnswer;
}

// The question a developer answers before a secret is shared with another
// project (spec §7.2, docs/adr/0020). A grant extends authority, so it is asked
// the way a profile approval is: on a terminal, with "unavailable" never
// treated as consent. Every field is an identifier or an alias; no value.
export interface GrantQuestion {
  readonly ownerProjectId: string;
  readonly alias: string;
  readonly targetProjectId: string;
  readonly targetAlias: string;
}

export interface GrantApprover {
  available(): boolean;
  ask(question: GrantQuestion): ProfileAnswer;
}

// The two questions `ward unregister` asks (DEC-217 Q4): whether to withdraw
// this checkout's binding, and — only when it has approvals — whether to
// remove them too. Identifiers and a count; no value.
export interface UnregisterQuestion {
  readonly kind: "binding" | "approvals";
  readonly projectId: string;
  readonly root: string;
  readonly approvals: number;
}

export interface UnregisterApprover {
  available(): boolean;
  ask(question: UnregisterQuestion): ProfileAnswer;
}
