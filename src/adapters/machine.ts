// The OS identity Ward records on the events of a run (spec §9.4's "observed
// OS identity"). Reading the platform is an adapter's job: the grammar that
// decides what a record may hold lives in the domain, and the application
// layer takes what this returns as an injected port, the way it takes the
// clock and the identifier source.
//
// Nothing here authorizes anything, and nothing here fails a command. A uid
// with no passwd entry makes `userInfo()` throw, which is ordinary inside a
// container, and a machine that cannot name itself is still allowed to run:
// the event then records that Ward observed no identity, which is true, rather
// than the run being refused over a field the platform does not have.
import { hostname, userInfo } from "node:os";
import {
  type ObservedMachine,
  observedMachine,
} from "../domain/vault-state.ts";

export function observeMachine(): ObservedMachine | null {
  try {
    return observedMachine(userInfo().username, hostname());
  } catch {
    return null;
  }
}
