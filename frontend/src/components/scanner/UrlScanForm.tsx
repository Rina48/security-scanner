import type { FormEvent } from "react";
import type { ScanMode } from "../../types";

interface UrlScanFormProps {
  targetUrl: string;
  mode: ScanMode;
  credentialCheck: boolean;
  isRunning: boolean;
  onTargetUrlChange: (value: string) => void;
  onModeChange: (mode: ScanMode) => void;
  onCredentialCheckChange: (value: boolean) => void;
  onSubmit: (event: FormEvent) => void;
}

export function UrlScanForm({
  targetUrl,
  mode,
  credentialCheck,
  isRunning,
  onTargetUrlChange,
  onModeChange,
  onCredentialCheckChange,
  onSubmit,
}: UrlScanFormProps) {
  return (
    <>
      <p className="lead">
        Pasif tarama tüm hedefler için çalışır. Aktif testler yalnızca politika tarafından
        izin verilen yerel/lab sunucularda çalışır.
      </p>
      <form className="scan-form" onSubmit={onSubmit}>
        <label htmlFor="target-url">
          Hedef URL
          <input
            id="target-url"
            type="url"
            required
            value={targetUrl}
            onChange={(e) => onTargetUrlChange(e.target.value)}
            placeholder="https://hedef-adres.local"
            disabled={isRunning}
            autoComplete="url"
          />
        </label>
        <label htmlFor="scan-mode">
          Tarama modu
          <select
            id="scan-mode"
            value={mode}
            onChange={(e) => onModeChange(e.target.value as ScanMode)}
            disabled={isRunning}
          >
            <option value="passive">Pasif</option>
            <option value="active">Aktif (sadece yerel/lab)</option>
          </select>
        </label>
        {mode === "active" ? (
          <label className="checkbox-label">
            <input
              type="checkbox"
              checked={credentialCheck}
              onChange={(e) => onCredentialCheckChange(e.target.checked)}
              aria-describedby="credential-check-desc"
              disabled={isRunning}
            />
            <span id="credential-check-desc">
              Varsayılan kimlik bilgisi testi (admin/admin, root/root vb.) — sadece izinli hedeflerde
            </span>
          </label>
        ) : null}
        {isRunning ? (
          <div className="scan-loading" role="status" aria-live="polite" aria-busy="true">
            <div className="scan-loading-bar">
              <div className="scan-loading-bar-fill" />
            </div>
            <p className="scan-loading-text">Tarama yapılıyor — bu işlem birkaç dakika sürebilir…</p>
          </div>
        ) : (
          <button type="submit" className="btn-primary">
            Taramayı Başlat
          </button>
        )}
      </form>
    </>
  );
}
