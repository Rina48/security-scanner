import assert from "node:assert/strict";
import test from "node:test";
import { fetchRobotsPaths } from "./robotsParser.js";

test("robots request receives parent abort and does not become an empty success", async () => {
  const controller = new AbortController();
  let requestSignal: AbortSignal | undefined;
  let markStarted: (() => void) | undefined;
  const started = new Promise<void>((resolve) => {
    markStarted = resolve;
  });

  const robots = fetchRobotsPaths("https://example.test", {
    fetchText: async (_url, init) => {
      requestSignal = init?.signal;
      assert.ok(requestSignal);
      markStarted?.();
      return new Promise((_resolve, reject) => {
        requestSignal?.addEventListener(
          "abort",
          () => reject(requestSignal?.reason),
          { once: true },
        );
      });
    },
    signal: controller.signal,
    timeoutMs: 10_000,
  });

  await started;
  controller.abort();

  await assert.rejects(robots, { name: "AbortError" });
  assert.equal(requestSignal?.aborted, true);
});
