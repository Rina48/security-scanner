import { readdir } from "node:fs/promises";
import { join } from "node:path";

export async function findTestFiles(rootDirectory: string): Promise<string[]> {
  const entries = await readdir(rootDirectory, { withFileTypes: true });
  const nested = await Promise.all(
    entries.map(async (entry) => {
      const fullPath = join(rootDirectory, entry.name);
      if (entry.isDirectory()) return findTestFiles(fullPath);
      return entry.isFile() && entry.name.endsWith(".test.js") ? [fullPath] : [];
    }),
  );
  return nested.flat().sort();
}

export function ensureTestsDiscovered(testFiles: readonly string[]): void {
  if (testFiles.length === 0) {
    throw new Error("No compiled test files were discovered; refusing a false-green test run.");
  }
}
