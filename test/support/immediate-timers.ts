// A timer that fires at once and records the delay it was given (WCLI-53).
//
// A test asserting that a bound is applied does not need to wait the bound
// out. Waiting adds a wall-clock margin that runner contention can break —
// run 36565512667 read 474 ms against a 400 ms ceiling on bytes nobody had
// changed — and it proves less than it looks like it does. What this gives
// instead is the delay the code asked `setTimeout` for, deterministically,
// and the refusal that firing it produces. It does not by itself bound how
// long the call takes: a real delay added outside `globalThis.setTimeout` is
// invisible to it, so a caller that cares should keep a generous ceiling
// beside it (see key-provider.test.ts, "gives up at the bound").
//
// The handler is invoked as a microtask rather than inline, so the code under
// test starts its call before the timer fires — the order a real timer has.
// Firing inline would hand the call an already-aborted signal, which a
// signal-honouring store would then fail on for the wrong reason.
//
// Wrap only a call that cannot settle on its own. The handler is queued
// before the call's own continuation, so the bound wins the race against a
// fast success too: around a store that answers normally, `load` would be
// refused with `vault_key_unavailable` while `delays` still looked right.
// Every caller here pairs it with a fixture that hangs.
//
// It replaces `globalThis.setTimeout` and `globalThis.clearTimeout` for the
// duration, so `restore()` belongs in a `finally`. It must wrap only the call
// under test: another timer set while it is installed is fired at once and
// recorded too. `restore()` puts back only what this instance installed, so a
// second install that has taken over is not clobbered by the first one's
// restore; and because the originals are captured at module load, a wrapper
// installed after that point but displaced by this one is not put back (no
// caller here does that, and the alternative — capturing per install — is
// what leaves a fake installed forever).
export interface ImmediateTimers {
  // Every delay `setTimeout` was given, in order.
  readonly delays: number[];
  restore(): void;
}

// Captured once, at module load, not per install. A second install would
// otherwise capture the first one's fake as its "real", and restoring the
// second would leave the first still installed — which is how a nested
// install turns into a suite-wide fake nobody can put back.
const realSetTimeout = globalThis.setTimeout;
const realClearTimeout = globalThis.clearTimeout;

export function createImmediateTimers(): ImmediateTimers {
  const delays: number[] = [];
  const immediateSetTimeout = ((
    handler: () => void,
    delay?: number,
    ...rest: unknown[]
  ) => {
    delays.push(delay ?? 0);
    // The real signature allows arguments passed through to the handler; the
    // callers this exists for pass none, and one that did would be recorded
    // above rather than silently dropped.
    void rest;
    queueMicrotask(handler);
    return 0 as unknown as ReturnType<typeof setTimeout>;
  }) as typeof setTimeout;
  // `bounded` clears its timer in a finally; the id it gets back is the fake
  // one, and there is nothing real to clear.
  const immediateClearTimeout = (() => {}) as typeof clearTimeout;
  globalThis.setTimeout = immediateSetTimeout;
  globalThis.clearTimeout = immediateClearTimeout;
  return {
    delays,
    restore() {
      if (globalThis.setTimeout === immediateSetTimeout)
        globalThis.setTimeout = realSetTimeout;
      if (globalThis.clearTimeout === immediateClearTimeout)
        globalThis.clearTimeout = realClearTimeout;
    },
  };
}
