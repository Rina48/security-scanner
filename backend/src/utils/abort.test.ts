import assert from "node:assert/strict";
import test from "node:test";
import {
  abortableDelay,
  createTimeoutSignal,
  withTimeoutSignal,
} from "./abort.js";

function rejectOnAbort(signal: AbortSignal): Promise<never> {
  return new Promise((_resolve, reject) => {
    const onAbort = (): void => reject(signal.reason);
    if (signal.aborted) onAbort();
    else signal.addEventListener("abort", onAbort, { once: true });
  });
}

test("parent abort is propagated through the timeout signal", async () => {
  const controller = new AbortController();
  let requestSignal: AbortSignal | undefined;
  const operation = withTimeoutSignal(controller.signal, 10_000, (signal) => {
    requestSignal = signal;
    return rejectOnAbort(signal);
  });

  controller.abort();
  await assert.rejects(operation, { name: "AbortError" });
  assert.equal(requestSignal?.aborted, true);
});

test("per-request timeout remains active without a parent signal", async () => {
  await assert.rejects(
    withTimeoutSignal(undefined, 20, rejectOnAbort),
    { name: "TimeoutError" },
  );
});

test("disposing a timeout scope removes both parent and timer effects", async () => {
  const controller = new AbortController();
  const scope = createTimeoutSignal(controller.signal, 20);
  scope.dispose();
  controller.abort();
  await new Promise((resolve) => setTimeout(resolve, 30));

  assert.equal(scope.signal.aborted, false);
});

test("abortable delay rejects promptly and clears its timer", async () => {
  const controller = new AbortController();
  const delay = abortableDelay(10_000, controller.signal);
  controller.abort();

  await assert.rejects(delay, { name: "AbortError" });
});
