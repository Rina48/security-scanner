import {
  MODE_TR,
  RISK_BADGE_CLASS,
  RISK_LEVEL_TR,
} from "../../pages/scannerPageConstants";
import type { ScanResult } from "../../types";

interface ScanHistoryCardProps {
  history: ScanResult[];
  onClearHistory: () => void;
  onSelectScan: (scan: ScanResult) => void;
}

export function ScanHistoryCard({
  history,
  onClearHistory,
  onSelectScan,
}: ScanHistoryCardProps) {
  return (
    <section className="card">
      <div className="history-header">
        <h2>Tarama Geçmişi</h2>
        {history.length > 0 ? (
          <button
            type="button"
            className="btn-secondary btn-clear-history"
            onClick={onClearHistory}
          >
            Geçmişi Temizle
          </button>
        ) : null}
      </div>
      {history.length === 0 ? (
        <div className="history-empty">
          <div className="history-empty-icon" aria-hidden="true">
            📋
          </div>
          <p>
            <strong>Henüz tarama yapılmadı</strong>
          </p>
          <p>Yukarıdaki formu doldurarak ilk taramanızı başlatın.</p>
        </div>
      ) : null}
      <ul className="history-list">
        {history.map((scan) => (
          <li
            key={scan.scanId}
            className="history-item-clickable"
            onClick={() => onSelectScan(scan)}
            title="Raporu görüntülemek için tıkla"
          >
            <span>{new Date(scan.completedAt).toLocaleString("tr-TR")}</span>
            <span>{scan.targetUrl}</span>
            <span>{MODE_TR[scan.mode]}</span>
            <span>
              <span className={RISK_BADGE_CLASS[scan.executiveSummary?.riskLevel ?? "clean"]}>
                {RISK_LEVEL_TR[scan.executiveSummary?.riskLevel ?? "clean"] ?? "-"}
              </span>
            </span>
          </li>
        ))}
      </ul>
    </section>
  );
}
