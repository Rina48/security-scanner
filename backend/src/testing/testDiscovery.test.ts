import assert from "node:assert/strict";
import test from "node:test";
import { ensureTestsDiscovered } from "./testDiscovery.js";

test("sıfır test keşfi false-green yerine hata üretir", () => {
  assert.throws(() => ensureTestsDiscovered([]), /No compiled test files/);
  assert.doesNotThrow(() => ensureTestsDiscovered(["one.test.js"]));
});
