import type { FormEvent } from "react";

interface BodyScanFormProps {
  pasteLabel: string;
  pasteBody: string;
  isRunning: boolean;
  onPasteLabelChange: (value: string) => void;
  onPasteBodyChange: (value: string) => void;
  onSubmit: (event: FormEvent) => void;
  onClear: () => void;
}

export function BodyScanForm({
  pasteLabel,
  pasteBody,
  isRunning,
  onPasteLabelChange,
  onPasteBodyChange,
  onSubmit,
  onClear,
}: BodyScanFormProps) {
  return (
    <>
      <p className="lead">
        Kaydedilmiş bir HTTP yanıt gövdesini (HTML dump, hata sayfası, JSON çıktısı vb.)
        yapıştırın ve herhangi bir ağ isteği atmadan çevrimdışı analiz edin.
      </p>
      <form className="scan-form" onSubmit={onSubmit}>
        <label>
          Kaynak etiketi (isteğe bağlı)
          <input
            type="text"
            value={pasteLabel}
            onChange={(e) => onPasteLabelChange(e.target.value)}
            placeholder="örn. https://example.com/hata veya debug-dump.txt"
          />
        </label>
        <label>
          Yanıt gövdesi
          <textarea
            required
            rows={12}
            value={pasteBody}
            onChange={(e) => onPasteBodyChange(e.target.value)}
            placeholder="HTTP yanıt gövdesini buraya yapıştırın..."
            className="body-textarea"
          />
        </label>
        <div className="body-actions">
          <button type="submit" disabled={isRunning || !pasteBody.trim()}>
            {isRunning ? "Analiz ediliyor..." : "Gövdeyi Analiz Et"}
          </button>
          {pasteBody ? (
            <button type="button" className="btn-secondary" onClick={onClear}>
              Temizle
            </button>
          ) : null}
        </div>
      </form>
    </>
  );
}
