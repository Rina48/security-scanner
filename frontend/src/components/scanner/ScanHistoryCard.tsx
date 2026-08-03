import {
  MODE_TR,
  RISK_BADGE_CLASS,
  RISK_LEVEL_TR,
} from "../../pages/scannerPageConstants";
import type { HistoryStatus } from "../../pages/scannerPageTypes";
import type { ScanResult } from "../../types";

interface ScanHistoryCardProps {
  history: ScanResult[];
  status: HistoryStatus;
  errorMessage: string;
  onClearHistory: () => void;
  onRetry: () => void;
  onSelectScan: (scan: ScanResult) => void;
}

export function ScanHistoryCard({
  history,
  status,
  errorMessage,
  onClearHistory,
  onRetry,
  onSelectScan,
}: ScanHistoryCardProps) {
  return (
    <section className="history-section" aria-labelledby="history-title">
      <div className="section-heading history-heading">
        <div>
          <p className="eyebrow">Kayıtlar</p>
          <h2 id="history-title">Tarama geçmişi</h2>
        </div>
        {status === "ready" && history.length > 0 ? (
          <button type="button" className="btn-danger-quiet" onClick={onClearHistory}>
            Geçmişi temizle
          </button>
        ) : null}
      </div>

      {status === "idle" ? (
        <HistoryState
          title="Geçmiş henüz yüklenmedi"
          description="Kayıtları görmek için API bağlantısı kurun."
        />
      ) : null}

      {status === "loading" ? (
        <div className="history-loading" role="status" aria-live="polite">
          <span className="activity-indicator" aria-hidden="true" />
          <div>
            <strong>Geçmiş yükleniyor</strong>
            <p>Bağlantı doğrulanırken kayıtlar getiriliyor.</p>
          </div>
        </div>
      ) : null}

      {status === "error" ? (
        <div className="history-error" role="alert">
          <div>
            <strong>Geçmiş yüklenemedi</strong>
            <p>{errorMessage}</p>
          </div>
          <button type="button" className="btn-secondary" onClick={onRetry}>
            Yeniden dene
          </button>
        </div>
      ) : null}

      {status === "ready" && history.length === 0 ? (
        <HistoryState
          title="Henüz tarama kaydı yok"
          description="Tamamlanan taramalar burada hedef, zaman, mod ve risk bilgisiyle görünür."
        />
      ) : null}

      {status === "ready" && history.length > 0 ? (
        <ul className="history-list">
          {history.map((scan) => (
            <li key={scan.scanId}>
              <button
                type="button"
                className="history-item"
                onClick={() => onSelectScan(scan)}
                aria-label={`${scan.targetUrl} raporunu aç`}
              >
                <span className="history-main">
                  <strong>{scan.targetUrl}</strong>
                  <span>{new Date(scan.completedAt).toLocaleString("tr-TR")}</span>
                </span>
                <span className="history-mode">{MODE_TR[scan.mode]}</span>
                <span className={RISK_BADGE_CLASS[scan.executiveSummary?.riskLevel ?? "clean"]}>
                  <span className="risk-badge-mark" aria-hidden="true" />
                  {RISK_LEVEL_TR[scan.executiveSummary?.riskLevel ?? "clean"] ?? "-"}
                </span>
                <span className="history-open" aria-hidden="true">
                  Aç
                </span>
              </button>
            </li>
          ))}
        </ul>
      ) : null}
    </section>
  );
}

function HistoryState({ title, description }: { title: string; description: string }) {
  return (
    <div className="history-empty">
      <strong>{title}</strong>
      <p>{description}</p>
    </div>
  );
}
