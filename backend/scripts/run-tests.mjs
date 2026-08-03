import { spawnSync } from "node:child_process";
import { resolve } from "node:path";
import {
  ensureTestsDiscovered,
  findTestFiles,
} from "../dist/testing/testDiscovery.js";

const testFiles = await findTestFiles(resolve("dist"));
ensureTestsDiscovered(testFiles);

const result = spawnSync(process.execPath, ["--test", ...testFiles], {
  stdio: "inherit",
});

if (result.error) throw result.error;
process.exitCode = result.status ?? 1;
