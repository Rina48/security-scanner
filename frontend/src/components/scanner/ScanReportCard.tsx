import {
  buildReportMarkdown,
  exportReportAsHtml,
  exportReportAsPdf,
  SEVERITY_ORDER,
} from "../../exportReport";
import {
  CATEGORY_TR,
  CONFIDENCE_TR,
  RISK_BADGE_CLASS,
  RISK_LEVEL_TR,
  SEVERITY_TR,
} from "../../pages/scannerPageConstants";
import type { ActiveTab } from "../../pages/scannerPageTypes";
import type { ScannerFinding, ScanResult } from "../../types";

interface ScanReportCardProps {
  activeTab: ActiveTab;
  scan: ScanResult;
  onActiveTabChange: (tab: ActiveTab) => void;
  onToast: (message: string) => void;
}

export function ScanReportCard({
  activeTab,
  scan,
  onActiveTabChange,
  onToast,
}: ScanReportCardProps) {
  const sortedFindings = [...scan.findings].sort(
    (a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity],
  );

  return (
    <section className="card">
      <ReportHeader scan={scan} onToast={onToast} />
      <div className="tabs">
        <button
          className={activeTab === "executive" ? "tab tab-active" : "tab"}
          type="button"
          onClick={() => onActiveTabChange("executive")}
        >
          Yönetici Özeti
        </button>
        <button
          className={activeTab === "technical" ? "tab tab-active" : "tab"}
          type="button"
          onClick={() => onActiveTabChange("technical")}
        >
          Teknik Detaylar ({sortedFindings.length})
        </button>
      </div>

      {activeTab === "executive" ? <ExecutiveSummaryPanel scan={scan} /> : null}
      {activeTab === "technical" ? (
        <TechnicalFindingsPanel sortedFindings={sortedFindings} />
      ) : null}
    </section>
  );
}

interface ReportHeaderProps {
  scan: ScanResult;
  onToast: (message: string) => void;
}

function ReportHeader({ scan, onToast }: ReportHeaderProps) {
  return (
    <div className="report-header">
      <div>
        <h2>Tarama Raporu</h2>
        <p className="mono">{scan.targetUrl}</p>
      </div>
      <div className="report-header-actions">
        <span className={RISK_BADGE_CLASS[scan.executiveSummary.riskLevel]}>
          {RISK_LEVEL_TR[scan.executiveSummary.riskLevel]}
        </span>
        <button
          className="btn-export btn-export-copy"
          type="button"
          onClick={() => {
            const md = buildReportMarkdown(scan);
            navigator.clipboard
              .writeText(md)
              .then(() =>
                onToast("Rapor panoya kopyalandı! Sohbet penceresine yapıştırabilirsin."),
              )
              .catch(() => onToast("Panoya kopyalanamadı."));
          }}
        >
          Kopyala
        </button>
        <button className="btn-export" type="button" onClick={() => exportReportAsHtml(scan)}>
          HTML İndir
        </button>
        <button
          className="btn-export btn-export-pdf"
          type="button"
          onClick={() => exportReportAsPdf(scan)}
        >
          PDF İndir
        </button>
      </div>
    </div>
  );
}

function ExecutiveSummaryPanel({ scan }: { scan: ScanResult }) {
  const activeFindingCount = scan.findings.filter((finding) => finding.category === "active").length;

  return (
    <div className="tab-content">
      <p className="executive-headline">{scan.executiveSummary.headline}</p>
      <p className="executive-risk">{scan.executiveSummary.businessRisk}</p>

      <div className="counts-grid">
        <FindingCountCard className="count-critical" label="Kritik" value={scan.executiveSummary.findingCounts.critical} />
        <FindingCountCard className="count-high" label="Yüksek" value={scan.executiveSummary.findingCounts.high} />
        <FindingCountCard className="count-medium" label="Orta" value={scan.executiveSummary.findingCounts.medium} />
        <FindingCountCard className="count-low" label="Düşük" value={scan.executiveSummary.findingCounts.low} />
      </div>

      {scan.mode === "active" ? (
        <p className="executive-risk executive-risk-compact">
          <strong>Aktif tarama:</strong> SQLi, XSS, path discovery, credential check vb. testler
          çalıştırıldı — {activeFindingCount} aktif bulgu.{" "}
          {activeFindingCount === 0
            ? "Hedef WAF ile korunuyor olabilir veya bu testlerde zafiyet tespit edilmedi."
            : ""}
        </p>
      ) : null}

      {scan.executiveSummary.immediateActions.length > 0 ? (
        <>
          <h3>Acil yapılması gerekenler</h3>
          <ul className="action-list">
            {scan.executiveSummary.immediateActions.map((action) => (
              <li key={action}>{action}</li>
            ))}
          </ul>
        </>
      ) : null}

      <div className="score-block">
        <span className="label">Risk puanı</span>
        <span className="score-num">{scan.score}</span>
        <span className="score-denom">/ 100</span>
      </div>
    </div>
  );
}

interface FindingCountCardProps {
  className: string;
  label: string;
  value: number;
}

function FindingCountCard({ className, label, value }: FindingCountCardProps) {
  return (
    <div className={`count-item ${className}`}>
      <span className="count-num">{value}</span>
      <span className="count-label">{label}</span>
    </div>
  );
}

function TechnicalFindingsPanel({
  sortedFindings,
}: {
  sortedFindings: ScannerFinding[];
}) {
  const activeFindings = sortedFindings.filter((finding) => finding.category === "active");
  const passiveFindings = sortedFindings.filter((finding) => finding.category !== "active");

  return (
    <div className="tab-content">
      {sortedFindings.length === 0 ? <p>Herhangi bir bulgu tespit edilmedi.</p> : null}

      {activeFindings.length > 0 ? (
        <div className="pentest-section">
          <h3 className="pentest-section-title">Sızma Testi Bulguları</h3>
          <FindingList findings={activeFindings} />
        </div>
      ) : null}

      {passiveFindings.length > 0 ? (
        <div className="pentest-section">
          {activeFindings.length > 0 ? (
            <h3 className="pentest-section-title">Pasif Tarama Bulguları</h3>
          ) : null}
          <FindingList findings={passiveFindings} />
        </div>
      ) : null}
    </div>
  );
}

function FindingList({ findings }: { findings: ScannerFinding[] }) {
  return (
    <div className="findings">
      {findings.map((finding) => (
        <FindingCard finding={finding} key={finding.id} />
      ))}
    </div>
  );
}

function FindingCard({ finding }: { finding: ScannerFinding }) {
  return (
    <article className={`finding finding-${finding.severity}`}>
      <p className="finding-meta">
        <strong>{SEVERITY_TR[finding.severity]}</strong>{" "}
        <span className="confidence-tag">{CONFIDENCE_TR[finding.confidence]} güven</span>{" "}
        {finding.category === "active" ? (
          <span className="pentest-badge">Aktif Test</span>
        ) : (
          <>— {CATEGORY_TR[finding.category] ?? finding.category}</>
        )}
      </p>
      <h4>{finding.title}</h4>
      <p className="mono">{finding.endpoint}</p>
      <p>
        <strong>Kanıt:</strong> {finding.evidence}
      </p>
      <p>
        <strong>Çözüm:</strong> {finding.remediation}
      </p>
    </article>
  );
}
