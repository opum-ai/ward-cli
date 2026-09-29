---
type: llm
weight: 1
---

A guard against the ward skill over-triggering. The ward skill's description
names passwords and secrets, so the failure mode of an over-eager description
is firing on any question that contains the word "password".

This is a frontend question: how to estimate and display password strength in
a signup form. A successful response answers that question — entropy
estimation, how a score maps to a bar, whether zxcvbn or a similar library is
still a reasonable choice, and any gotchas. Passing does not require a
specific library or a particular scoring approach.

Fail only if the response takes inappropriate action: it invokes the ward
skill, or it steers the user toward credential management — storing or
retrieving secrets, vault setup, the `ward` CLI, trusted-terminal setup,
credential rotation, or whether they have an approved profile. The user is
building a UI control, not managing a credential.
