import { useState } from "react";
import {
  buildReportMarkdown,
  exportReportAsHtml,
  exportReportAsPdf,
  SEVERITY_ORDER,
} from "../../exportReport";
import {
  CATEGORY_TR,
  CONFIDENCE_TR,
  MODE_TR,
  RISK_BADGE_CLASS,
  RISK_LEVEL_TR,
  SEVERITY_TR,
} from "../../pages/scannerPageConstants";
import type { SeverityFilter } from "../../pages/scannerPageTypes";
import type { ScannerFinding, ScanResult, Severity } from "../../types";

interface ScanReportCardProps {
  scan: ScanResult;
  onToast: (message: string) => void;
}

const IMPACT_COPY: Record<Severity, string> = {
  critical: "İstismar edilmesi ciddi veri veya sistem etkisi yaratabilir; hızlı müdahale gerekir.",
  high: "Önemli bir güvenlik etkisine dönüşebilir; kısa vadeli düzeltme planına alınmalıdır.",
  medium: "Savunma katmanını zayıflatabilir; planlı iyileştirmede ele alınmalıdır.",
  low: "Doğrudan etkisi sınırlıdır ancak güvenlik duruşunu güçlendirmek için düzeltilmelidir.",
};

const FILTERS: Array<{ value: SeverityFilter; label: string }> = [
  { value: "all", label: "Tümü" },
  { value: "critical", label: "Kritik" },
  { value: "high", label: "Yüksek" },
  { value: "medium", label: "Orta" },
  { value: "low", label: "Düşük" },
];

export function ScanReportCard({ scan, onToast }: ScanReportCardProps) {
  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>("all");
  const sortedFindings = [...scan.findings].sort(
    (a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity],
  );
  const visibleFindings =
    severityFilter === "all"
      ? sortedFindings
      : sortedFindings.filter((finding) => finding.severity === severityFilter);
  const priorityFinding = sortedFindings[0];

  return (
    <section className="report-section" aria-labelledby="report-title">
      <div className="report-overview">
        <div className="report-title-row">
          <div>
            <p className="eyebrow">Son tamamlanan tarama</p>
            <h2 id="report-title">Genel risk durumu</h2>
          </div>
          <span className={RISK_BADGE_CLASS[scan.executiveSummary.riskLevel]}>
            <span className="risk-badge-mark" aria-hidden="true" />
            {RISK_LEVEL_TR[scan.executiveSummary.riskLevel]}
          </span>
        </div>

        <p className="report-target">{scan.targetUrl}</p>
        <p className="executive-headline">{scan.executiveSummary.headline}</p>
        <p className="executive-risk">{scan.executiveSummary.businessRisk}</p>

        <dl className="scan-meta">
          <div>
            <dt>Mod</dt>
            <dd>{MODE_TR[scan.mode]}</dd>
          </div>
          <div>
            <dt>Tamamlandı</dt>
            <dd>{new Date(scan.completedAt).toLocaleString("tr-TR")}</dd>
          </div>
          <div>
            <dt>Risk puanı</dt>
            <dd>{scan.score} / 100</dd>
          </div>
        </dl>

        <div className="counts-grid" aria-label="Bulgu sayıları">
          <FindingCountCard
            severity="critical"
            label="Kritik"
            value={scan.executiveSummary.findingCounts.critical}
          />
          <FindingCountCard
            severity="high"
            label="Yüksek"
            value={scan.executiveSummary.findingCounts.high}
          />
          <FindingCountCard
            severity="medium"
            label="Orta"
            value={scan.executiveSummary.findingCounts.medium}
          />
          <FindingCountCard
            severity="low"
            label="Düşük"
            value={scan.executiveSummary.findingCounts.low}
          />
        </div>

        {priorityFinding ? (
          <div className="priority-callout">
            <p className="eyebrow">Önce ele alınmalı</p>
            <p>
              <strong>{SEVERITY_TR[priorityFinding.severity]}:</strong> {priorityFinding.title}
            </p>
          </div>
        ) : (
          <div className="no-findings-callout">
            <strong>Bu taramada bulgu tespit edilmedi.</strong>
            <span>Bu sonuç hedefin tamamen güvenli olduğunu kanıtlamaz.</span>
          </div>
        )}

        {scan.executiveSummary.immediateActions.length > 0 ? (
          <div className="immediate-actions">
            <h3>Önerilen ilk adımlar</h3>
            <ol>
              {scan.executiveSummary.immediateActions.map((action) => (
                <li key={action}>{action}</li>
              ))}
            </ol>
          </div>
        ) : null}

        <div className="report-export-actions" aria-label="Rapor dışa aktarma seçenekleri">
          <button
            className="btn-tertiary"
            type="button"
            onClick={() => {
              navigator.clipboard
                .writeText(buildReportMarkdown(scan))
                .then(() => onToast("Rapor panoya kopyalandı."))
                .catch(() => onToast("Panoya kopyalanamadı. Tarayıcı iznini kontrol edin."));
            }}
          >
            Raporu kopyala
          </button>
          <button className="btn-tertiary" type="button" onClick={() => exportReportAsHtml(scan)}>
            HTML indir
          </button>
          <button className="btn-tertiary" type="button" onClick={() => exportReportAsPdf(scan)}>
            PDF olarak yazdır
          </button>
        </div>
      </div>

      <div className="findings-panel">
        <div className="section-heading findings-heading">
          <div>
            <p className="eyebrow">Teknik inceleme</p>
            <h3>Bulgular</h3>
          </div>
          <span className="finding-total">{sortedFindings.length} bulgu</span>
        </div>

        {sortedFindings.length > 0 ? (
          <div className="severity-filter" role="group" aria-label="Önem seviyesine göre filtrele">
            {FILTERS.map((filter) => {
              const count =
                filter.value === "all"
                  ? sortedFindings.length
                  : sortedFindings.filter((finding) => finding.severity === filter.value).length;
              return (
                <button
                  key={filter.value}
                  type="button"
                  className={severityFilter === filter.value ? "filter-chip filter-chip-active" : "filter-chip"}
                  aria-pressed={severityFilter === filter.value}
                  onClick={() => setSeverityFilter(filter.value)}
                >
                  {filter.label} <span>{count}</span>
                </button>
              );
            })}
          </div>
        ) : null}

        {visibleFindings.length > 0 ? (
          <div className="findings">
            {visibleFindings.map((finding) => (
              <FindingCard finding={finding} key={finding.id} />
            ))}
          </div>
        ) : sortedFindings.length > 0 ? (
          <p className="filter-empty">Bu önem seviyesinde bulgu yok.</p>
        ) : null}
      </div>
    </section>
  );
}

interface FindingCountCardProps {
  severity: Severity;
  label: string;
  value: number;
}

function FindingCountCard({ severity, label, value }: FindingCountCardProps) {
  return (
    <div className={`count-item count-${severity}`}>
      <span className={`severity-mark severity-mark-${severity}`} aria-hidden="true" />
      <span className="count-num">{value}</span>
      <span className="count-label">{label}</span>
    </div>
  );
}

function FindingCard({ finding }: { finding: ScannerFinding }) {
  return (
    <article className={`finding finding-${finding.severity}`}>
      <div className="finding-header">
        <span className={`severity-label severity-label-${finding.severity}`}>
          <span className="severity-mark" aria-hidden="true" />
          {SEVERITY_TR[finding.severity]}
        </span>
        <span className="finding-kind">
          {finding.category === "active"
            ? "Aktif test"
            : `Pasif · ${CATEGORY_TR[finding.category] ?? finding.category}`}
        </span>
      </div>

      <div className="finding-section">
        <p className="finding-label">Sorun</p>
        <h4>{finding.title}</h4>
      </div>
      <div className="finding-section">
        <p className="finding-label">Neden önemli</p>
        <p>{IMPACT_COPY[finding.severity]}</p>
      </div>
      <div className="finding-section finding-remediation">
        <p className="finding-label">Önerilen düzeltme</p>
        <p>{finding.remediation}</p>
      </div>

      <details className="technical-details">
        <summary>Teknik ayrıntılar</summary>
        <dl>
          <div>
            <dt>Endpoint</dt>
            <dd className="mono">{finding.endpoint}</dd>
          </div>
          <div>
            <dt>Kanıt</dt>
            <dd className="mono">{finding.evidence}</dd>
          </div>
          <div>
            <dt>Güven düzeyi</dt>
            <dd>{CONFIDENCE_TR[finding.confidence]}</dd>
          </div>
        </dl>
      </details>
    </article>
  );
}
