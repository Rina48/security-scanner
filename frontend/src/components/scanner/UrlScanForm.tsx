import type { FormEvent } from "react";
import type { ScanMode } from "../../types";

interface UrlScanFormProps {
  targetUrl: string;
  mode: ScanMode;
  credentialCheck: boolean;
  isRunning: boolean;
  isConnected: boolean;
  urlError: string;
  onTargetUrlChange: (value: string) => void;
  onTargetUrlBlur: () => void;
  onModeChange: (mode: ScanMode) => void;
  onCredentialCheckChange: (value: boolean) => void;
  onSubmit: (event: FormEvent) => void;
}

export function UrlScanForm({
  targetUrl,
  mode,
  credentialCheck,
  isRunning,
  isConnected,
  urlError,
  onTargetUrlChange,
  onTargetUrlBlur,
  onModeChange,
  onCredentialCheckChange,
  onSubmit,
}: UrlScanFormProps) {
  return (
    <form className="scan-form" onSubmit={onSubmit} noValidate>
      <div className="field-group">
        <label htmlFor="target-url">Hedef URL</label>
        <input
          id="target-url"
          type="url"
          required
          value={targetUrl}
          onChange={(event) => onTargetUrlChange(event.target.value)}
          onBlur={onTargetUrlBlur}
          placeholder="https://hedef-adres.local"
          disabled={isRunning}
          autoComplete="url"
          inputMode="url"
          aria-invalid={Boolean(urlError)}
          aria-describedby={urlError ? "target-url-error" : undefined}
        />
        {urlError ? (
          <p id="target-url-error" className="field-error" role="alert">
            {urlError}
          </p>
        ) : null}
      </div>

      <fieldset className="mode-fieldset" disabled={isRunning}>
        <legend>Tarama türü</legend>
        <div className="mode-options">
          <label className={mode === "passive" ? "mode-option mode-option-selected" : "mode-option"}>
            <input
              type="radio"
              name="scan-mode"
              value="passive"
              checked={mode === "passive"}
              onChange={() => onModeChange("passive")}
            />
            <span>
              <strong>Pasif tarama</strong>
              <small>Yanıtı, başlıkları, çerezleri ve TLS bilgisini inceler.</small>
            </span>
          </label>
          <label className={mode === "active" ? "mode-option mode-option-selected" : "mode-option"}>
            <input
              type="radio"
              name="scan-mode"
              value="active"
              checked={mode === "active"}
              onChange={() => onModeChange("active")}
            />
            <span>
              <strong>Aktif tarama</strong>
              <small>Yalnız sunucuda izin verilmiş local veya lab hedeflerine probe gönderir.</small>
            </span>
          </label>
        </div>
      </fieldset>

      {mode === "active" ? (
        <div className="active-scan-options">
          <p className="boundary-note">
            Aktif tarama sadece açıkça yetkilendirilmiş local veya lab hedeflerinde çalışır.
          </p>
          <label className="checkbox-label">
            <input
              type="checkbox"
              checked={credentialCheck}
              onChange={(event) => onCredentialCheckChange(event.target.checked)}
              aria-describedby="credential-check-risk"
              disabled={isRunning}
            />
            <span>
              <strong>Varsayılan kimlik bilgilerini kontrol et</strong>
              <small id="credential-check-risk">
                Bu seçenek hesap kilidine veya kısa süreli yoğun isteğe yol açabilir.
              </small>
            </span>
          </label>
        </div>
      ) : null}

      <button
        type="submit"
        className="btn-primary"
        disabled={isRunning || !isConnected}
      >
        {isRunning ? "Tarama sürüyor…" : "Taramayı başlat"}
      </button>
      {!isConnected ? (
        <p className="submit-hint">Taramayı başlatmak için önce API bağlantısı kurun.</p>
      ) : null}
    </form>
  );
}
