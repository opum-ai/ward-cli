// The port through which a developer answers Ward's one interactive
// question: whether to register this checkout for a project.
//
// Spec §4.3 is explicit about what an interactive gate is worth: it reduces
// mistakes, and it is not proof of human identity. So the outcome is
// three-valued rather than a boolean. "unavailable" means Ward had no
// interactive terminal to ask on, and is never treated as consent or as a
// refusal — a caller that cannot ask must not act (spec §7.1).

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
