import { useEffect, useRef, useState } from "react";
import type { ConfirmState } from "../../pages/scannerPageTypes";

interface ConfirmDialogProps {
  confirmState: ConfirmState;
  onCancel: () => void;
}

export function ConfirmDialog({ confirmState, onCancel }: ConfirmDialogProps) {
  const [isConfirming, setIsConfirming] = useState(false);
  const cancelButtonRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    cancelButtonRef.current?.focus();
    const handleKeyDown = (event: KeyboardEvent): void => {
      if (event.key === "Escape" && !isConfirming) onCancel();
    };
    document.addEventListener("keydown", handleKeyDown);
    return () => document.removeEventListener("keydown", handleKeyDown);
  }, [isConfirming, onCancel]);

  async function handleConfirm(): Promise<void> {
    if (isConfirming) return;
    setIsConfirming(true);
    try {
      await confirmState.onConfirm();
      onCancel();
    } finally {
      setIsConfirming(false);
    }
  }

  return (
    <div className="modal-backdrop">
      <div
        className="confirm-dialog"
        role="alertdialog"
        aria-modal="true"
        aria-labelledby="confirm-dialog-title"
        aria-describedby="confirm-dialog-description"
      >
        <p className="eyebrow">Onay gerekli</p>
        <h2 id="confirm-dialog-title">Geçmiş temizlensin mi?</h2>
        <p id="confirm-dialog-description">{confirmState.message}</p>
        <div className="confirm-dialog-actions">
          <button
            ref={cancelButtonRef}
            type="button"
            className="btn-secondary"
            onClick={onCancel}
            disabled={isConfirming}
          >
            İptal
          </button>
          <button
            type="button"
            className="btn-danger"
            onClick={() => void handleConfirm()}
            disabled={isConfirming}
          >
            {isConfirming ? "Siliniyor…" : "Evet, geçmişi sil"}
          </button>
        </div>
      </div>
    </div>
  );
}
