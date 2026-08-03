import type { FormEvent } from "react";

interface BodyScanFormProps {
  pasteLabel: string;
  pasteBody: string;
  isRunning: boolean;
  isConnected: boolean;
  onPasteLabelChange: (value: string) => void;
  onPasteBodyChange: (value: string) => void;
  onSubmit: (event: FormEvent) => void;
  onClear: () => void;
}

export function BodyScanForm({
  pasteLabel,
  pasteBody,
  isRunning,
  isConnected,
  onPasteLabelChange,
  onPasteBodyChange,
  onSubmit,
  onClear,
}: BodyScanFormProps) {
  return (
    <form className="scan-form" onSubmit={onSubmit}>
      <p className="flow-description">
        Kaydedilmiş HTML, JSON veya hata çıktısını ağ isteği göndermeden analiz edin.
      </p>
      <label htmlFor="source-label">
        Kaynak etiketi <span className="optional-label">İsteğe bağlı</span>
        <input
          id="source-label"
          type="text"
          value={pasteLabel}
          onChange={(event) => onPasteLabelChange(event.target.value)}
          placeholder="Örneğin: debug-dump.txt"
          disabled={isRunning}
          maxLength={512}
        />
      </label>
      <label htmlFor="response-body">
        Yanıt gövdesi
        <textarea
          id="response-body"
          required
          rows={12}
          value={pasteBody}
          onChange={(event) => onPasteBodyChange(event.target.value)}
          placeholder="HTTP yanıt gövdesini buraya yapıştırın…"
          className="body-textarea"
          disabled={isRunning}
        />
      </label>
      <div className="form-actions">
        <button
          type="submit"
          className="btn-primary"
          disabled={isRunning || !isConnected || !pasteBody.trim()}
        >
          {isRunning ? "Analiz sürüyor…" : "Yanıtı analiz et"}
        </button>
        {pasteBody ? (
          <button
            type="button"
            className="btn-secondary"
            onClick={onClear}
            disabled={isRunning}
          >
            Alanları temizle
          </button>
        ) : null}
      </div>
      {!isConnected ? (
        <p className="submit-hint">Analizi başlatmak için önce API bağlantısı kurun.</p>
      ) : null}
    </form>
  );
}
