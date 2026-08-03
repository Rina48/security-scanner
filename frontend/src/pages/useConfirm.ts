import { useState } from "react";
import type { ConfirmState } from "./scannerPageTypes";

export function useConfirm(): {
  confirmState: ConfirmState | null;
  showConfirm: (message: string, onConfirm: () => void | Promise<void>) => void;
  closeConfirm: () => void;
} {
  const [confirmState, setConfirmState] = useState<ConfirmState | null>(null);

  function showConfirm(message: string, onConfirm: () => void | Promise<void>): void {
    setConfirmState({ message, onConfirm });
  }

  function closeConfirm(): void {
    setConfirmState(null);
  }

  return { confirmState, showConfirm, closeConfirm };
}
