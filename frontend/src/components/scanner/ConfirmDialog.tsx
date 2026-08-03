import type { ConfirmState } from "../../pages/scannerPageTypes";

interface ConfirmDialogProps {
  confirmState: ConfirmState;
  onCancel: () => void;
}

export function ConfirmDialog({ confirmState, onCancel }: ConfirmDialogProps) {
  return (
    <div className="modal-backdrop" role="dialog" aria-modal="true">
      <div className="card confirm-dialog">
        <p>{confirmState.message}</p>
        <div className="confirm-dialog-actions">
          <button type="button" className="btn-secondary" onClick={onCancel}>
            İptal
          </button>
          <button
            type="button"
            onClick={() => {
              void confirmState.onConfirm();
              onCancel();
            }}
          >
            Evet, sil
          </button>
        </div>
      </div>
    </div>
  );
}
