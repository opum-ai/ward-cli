// A timer that fires at once and records the delay it was given (WCLI-53).
//
// A test asserting that a bound is applied does not need to wait the bound
// out. Waiting proves the same property — the bound is what ends the call —
// while adding a wall-clock margin that runner contention can break: run
// 36565512667 read 474 ms against a 400 ms ceiling on bytes nobody had
// changed. With this in place the assertions are the delay the code asked
// for and the refusal that firing it produces, both deterministic.
//
// It replaces `globalThis.setTimeout` and `globalThis.clearTimeout` for the
// duration, so `restore()` belongs in a `finally`, and it must wrap only the
// call under test: another timer set while it is installed is fired at once
// and recorded too.
export interface ImmediateTimers {
  // Every delay `setTimeout` was given, in order.
  readonly delays: number[];
  restore(): void;
}

export function createImmediateTimers(): ImmediateTimers {
  const delays: number[] = [];
  const realSetTimeout = globalThis.setTimeout;
  const realClearTimeout = globalThis.clearTimeout;
  globalThis.setTimeout = ((
    handler: () => void,
    delay?: number,
    ...rest: unknown[]
  ) => {
    delays.push(delay ?? 0);
    // The real signature allows arguments passed through to the handler; the
    // callers this exists for pass none, and one that did would be recorded
    // above rather than silently dropped.
    void rest;
    handler();
    return 0 as unknown as ReturnType<typeof setTimeout>;
  }) as typeof setTimeout;
  // `bounded` clears its timer in a finally; the id it gets back is the fake
  // one, and there is nothing real to clear.
  globalThis.clearTimeout = (() => {}) as typeof clearTimeout;
  return {
    delays,
    restore() {
      globalThis.setTimeout = realSetTimeout;
      globalThis.clearTimeout = realClearTimeout;
    },
  };
}
