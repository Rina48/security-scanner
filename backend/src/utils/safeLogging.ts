import { maskSecrets } from "./secretMasker.js";

export function safeErrorMessage(error: unknown): string {
  return maskSecrets(error instanceof Error ? error.message : String(error));
}

export function logRedactedError(message: string, error: unknown): void {
  console.error(maskSecrets(message), safeErrorMessage(error));
}
