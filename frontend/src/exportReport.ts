import type { ScanResult, Severity } from "./types";

export const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 1,
  high: 2,
  medium: 3,
  low: 4,
};

const RISK_BADGE_COLOR: Record<string, string> = {
  critical: "#dc2626",
  high: "#ea580c",
  medium: "#ca8a04",
  low: "#16a34a",
  clean: "#16a34a",
};

// Mojibake düzeltme tablosu: UTF-8 baytlarının Latin-1 olarak okunduğunda ürettiği
// yaygın bozuk karakter dizilerini doğru Unicode karakterlere çevirir.
const MOJIBAKE_MAP: Array<[RegExp, string]> = [
  [/â€¦/g, "…"],
  [/â€™/g, "'"],
  [/â€œ/g, '"'],
  [/â€/g, '"'],
  [/â€¢/g, "•"],
  [/Â·/g, "·"],
  [/Â /g, " "],
  [/Â/g, ""],
  [/â‚¬/g, "€"],
  [/Ã©/g, "é"],
  [/Ã¼/g, "ü"],
  [/Ã¶/g, "ö"],
  [/Ã§/g, "ç"],
  [/Ä±/g, "ı"],
  [/\uFFFD/g, ""],
];

const HTML_ESCAPE_MAP: Record<string, string> = {
  "&": "&amp;",
  "<": "&lt;",
  ">": "&gt;",
  '"': "&quot;",
};

function fixEncoding(text: string): string {
  let fixed = text;
  for (const [pattern, replacement] of MOJIBAKE_MAP) {
    fixed = fixed.replace(pattern, replacement);
  }
  return fixed;
}

function escapeHtml(text: string): string {
  return fixEncoding(text).replace(/[&<>"]/g, (char) => HTML_ESCAPE_MAP[char]);
}

export function buildReportMarkdown(scan: ScanResult): string {
  const lines: string[] = [
    `# Güvenlik Tarama Raporu`,
    ``,
    `**Hedef:** ${scan.targetUrl}`,
    `**Mod:** ${scan.mode === "passive" ? "Pasif" : "Aktif"}`,
    `**Tarih:** ${new Date(scan.completedAt).toLocaleString("tr-TR")}`,
    `**Skor:** ${scan.score}/100`,
    `**Risk Seviyesi:** ${scan.executiveSummary.riskLevel.toUpperCase()}`,
    ``,
    `## Özet`,
    ``,
    scan.executiveSummary.headline,
    ``,
    scan.executiveSummary.businessRisk,
    ``,
    `| Kritik | Yüksek | Orta | Düşük |`,
    `|--------|--------|------|-------|`,
    `| ${scan.executiveSummary.findingCounts.critical} | ${scan.executiveSummary.findingCounts.high} | ${scan.executiveSummary.findingCounts.medium} | ${scan.executiveSummary.findingCounts.low} |`,
    ``,
  ];

  if (scan.executiveSummary.immediateActions.length > 0) {
    lines.push(`## Acil Eylemler`, ``);
    scan.executiveSummary.immediateActions.forEach((a, i) => lines.push(`${i + 1}. ${a}`));
    lines.push(``);
  }

  lines.push(`## Bulgular`, ``);
  const sorted = [...scan.findings].sort(
    (a, b) => (SEVERITY_ORDER[a.severity] ?? 9) - (SEVERITY_ORDER[b.severity] ?? 9),
  );

  for (const f of sorted) {
    lines.push(
      `### [${f.severity.toUpperCase()}] ${f.title}`,
      `- **Kategori:** ${f.category}`,
      `- **Güven:** ${f.confidence}`,
      `- **Endpoint:** ${f.endpoint}`,
      `- **Kanıt:** ${f.evidence}`,
      `- **Çözüm:** ${f.remediation}`,
      ``,
    );
  }

  return lines.join("\n");
}

function buildReportHtml(scan: ScanResult, forPrint = false): string {
  const ex = scan.executiveSummary ?? {
    riskLevel: "low" as const,
    headline: "",
    businessRisk: "",
    immediateActions: [],
    findingCounts: { critical: 0, high: 0, medium: 0, low: 0 },
  };
  const badgeColor = RISK_BADGE_COLOR[ex.riskLevel] ?? "#6b7280";

  const sortedFindings = [...scan.findings].sort(
    (a, b) => (SEVERITY_ORDER[a.severity] ?? 9) - (SEVERITY_ORDER[b.severity] ?? 9),
  );

  return `<!DOCTYPE html>
<html lang="tr">
<head>
  <meta charset="UTF-8"/>
  <title>Güvenlik Tarama Raporu — ${escapeHtml(scan.targetUrl)}</title>
  <style>
    /* ── Temel ── */
    body { font-family: "Segoe UI", Arial, sans-serif; margin: 0; background: #f3f6f9; color: #17202a; }
    .wrap { max-width: 900px; margin: 0 auto; padding: 40px 24px; }
    h1 { font-size: 28px; margin: 0 0 8px; }
    h2 { font-size: 20px; margin: 32px 0 12px; border-bottom: 2px solid #e2e8f0; padding-bottom: 8px; }
    h3 { font-size: 15px; margin: 20px 0 8px; }
    .badge { display: inline-block; padding: 4px 12px; border-radius: 99px; color: #fff; font-weight: 700; font-size: 13px; background: ${badgeColor}; -webkit-print-color-adjust: exact; print-color-adjust: exact; }
    .meta { color: #64748b; font-size: 14px; margin: 8px 0 24px; }
    .card { background: #fff; border: 1px solid #dce5ee; border-radius: 12px; padding: 24px; margin-bottom: 24px; }
    .counts { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; }
    .count-item { text-align: center; padding: 12px; border: 1px solid #e2e8f0; border-radius: 8px; }
    .count-num { font-size: 36px; font-weight: 700; display: block; line-height: 1.1; }
    .count-label { font-size: 11px; text-transform: uppercase; color: #64748b; margin-top: 4px; display: block; }
    .count-critical .count-num { color: #dc2626; }
    .count-high .count-num    { color: #ea580c; }
    .count-medium .count-num  { color: #ca8a04; }
    .count-low .count-num     { color: #16a34a; }
    table { width: 100%; border-collapse: collapse; font-size: 13px; }
    th { text-align: left; background: #f1f5f9; padding: 10px 12px; font-size: 12px; text-transform: uppercase; -webkit-print-color-adjust: exact; print-color-adjust: exact; }
    td { padding: 10px 12px; border-bottom: 1px solid #e2e8f0; vertical-align: top; }
    code { font-family: "Consolas", monospace; font-size: 11px; word-break: break-all; }
    ul { margin: 8px 0; padding-left: 20px; }
    li { margin-bottom: 6px; line-height: 1.5; }
    .score { font-size: 48px; font-weight: 700; color: #0f4c81; }
    .score-row { display: flex; align-items: baseline; gap: 8px; margin-top: 16px; }
    .score-denom { font-size: 24px; color: #64748b; }
    .footer { color: #94a3b8; font-size: 11px; margin-top: 40px; text-align: center; border-top: 1px solid #e2e8f0; padding-top: 16px; }
    .sev-critical { color: #dc2626; font-weight: 700; text-transform: uppercase; }
    .sev-high     { color: #ea580c; font-weight: 700; text-transform: uppercase; }
    .sev-medium   { color: #ca8a04; font-weight: 700; text-transform: uppercase; }
    .sev-low      { color: #16a34a; font-weight: 700; text-transform: uppercase; }
    .finding-block { border-left: 4px solid #e2e8f0; padding: 12px 16px; margin: 12px 0; background: #f8fafc; border-radius: 0 8px 8px 0; }
    .finding-block.sev-critical { border-left-color: #dc2626; }
    .finding-block.sev-high     { border-left-color: #ea580c; }
    .finding-block.sev-medium   { border-left-color: #ca8a04; }
    .finding-block.sev-low      { border-left-color: #16a34a; }
    .finding-title { font-weight: 700; font-size: 14px; margin: 0 0 8px; }
    .finding-field { font-size: 12px; margin: 4px 0; line-height: 1.5; }
    .finding-field strong { color: #374151; }

    /* ── Baskı / PDF ── */
    @page {
      size: A4;
      margin: 18mm 15mm 18mm 15mm;
    }
    @media print {
      body { background: #fff; }
      .wrap { padding: 0; max-width: 100%; }
      .card { border: 1px solid #ccc; border-radius: 0; page-break-inside: avoid; box-shadow: none; }
      .finding-block { page-break-inside: avoid; }
      .no-print { display: none !important; }
      a { color: inherit; text-decoration: none; }
    }
  </style>
  ${forPrint ? `<script>window.addEventListener('load', function() {
    setTimeout(function() { window.print(); }, 400);
  });</script>` : ""}
</head>
<body>
<div class="wrap">

  <h1>Güvenlik Tarama Raporu</h1>
  <p class="meta">
    <span class="badge">${escapeHtml(ex.riskLevel.toUpperCase())}</span>&nbsp;
    ${escapeHtml(scan.targetUrl)} &bull; ${new Date(scan.completedAt).toLocaleString("tr-TR")} &bull; Mod: ${escapeHtml(scan.mode)}
  </p>

  <!-- YÖNETİCİ ÖZETİ -->
  <div class="card">
    <h2 style="margin-top:0">Yönetici Özeti</h2>
    <p style="font-size:17px;font-weight:600;margin-bottom:8px">${escapeHtml(ex.headline)}</p>
    <p style="color:#374151;margin-bottom:20px">${escapeHtml(ex.businessRisk)}</p>
    <div class="counts">
      <div class="count-item count-critical"><span class="count-num">${ex.findingCounts.critical}</span><span class="count-label">Kritik</span></div>
      <div class="count-item count-high"><span class="count-num">${ex.findingCounts.high}</span><span class="count-label">Yüksek</span></div>
      <div class="count-item count-medium"><span class="count-num">${ex.findingCounts.medium}</span><span class="count-label">Orta</span></div>
      <div class="count-item count-low"><span class="count-num">${ex.findingCounts.low}</span><span class="count-label">Düşük</span></div>
    </div>
    ${ex.immediateActions.length > 0 ? `<h3>Acil Yapılması Gerekenler</h3><ul>${ex.immediateActions.map((a) => `<li>${escapeHtml(a)}</li>`).join("")}</ul>` : ""}
    <div class="score-row">
      <span style="color:#64748b;font-size:12px;text-transform:uppercase;letter-spacing:.05em">Risk Puanı</span>
      <span class="score">${scan.score}</span>
      <span class="score-denom">/ 100</span>
    </div>
  </div>

  <!-- TEKNİK EK -->
  <div class="card">
    <h2 style="margin-top:0">Teknik Ek — Tüm Bulgular (${sortedFindings.length})</h2>
    ${
      sortedFindings.length === 0
        ? "<p>Herhangi bir bulgu tespit edilmedi.</p>"
        : sortedFindings.map((f) => `
      <div class="finding-block sev-${f.severity}">
        <p class="finding-title">
          <span class="sev-${f.severity}">${escapeHtml(f.severity.toUpperCase())}</span>
          &nbsp;—&nbsp;${escapeHtml(f.title)}
        </p>
        <p class="finding-field"><strong>Kategori:</strong> ${escapeHtml(f.category)} &nbsp;|&nbsp; <strong>Güven:</strong> ${escapeHtml(f.confidence)}</p>
        <p class="finding-field"><strong>Endpoint:</strong> <code>${escapeHtml(f.endpoint)}</code></p>
        <p class="finding-field"><strong>Kanıt:</strong> <code>${escapeHtml(f.evidence)}</code></p>
        <p class="finding-field"><strong>Çözüm:</strong> ${escapeHtml(f.remediation)}</p>
      </div>`).join("")
    }
  </div>

  <p class="footer">Security Scanner tarafından oluşturuldu &bull; Tarama ID: ${escapeHtml(scan.scanId)}</p>
</div>
</body>
</html>`;
}

export function exportReportAsHtml(scan: ScanResult): void {
  if (!scan) return;
  const html = buildReportHtml(scan, false);
  const blob = new Blob([html], { type: "text/html;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = `scan-report-${scan.scanId.slice(0, 8)}.html`;
  anchor.style.display = "none";
  document.body.appendChild(anchor);
  anchor.click();
  document.body.removeChild(anchor);
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export function exportReportAsPdf(scan: ScanResult): void {
  if (!scan) return;
  const html = buildReportHtml(scan, true);
  const blob = new Blob([html], { type: "text/html;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  // Yeni pencerede aç — otomatik print diyaloğu PDF olarak kaydettirmeyi sağlar.
  const win = window.open(url, "_blank", "width=900,height=700,menubar=no,toolbar=no");
  if (!win) {
    // Popup engellenirse fallback: sekme olarak aç.
    window.open(url, "_blank");
  }
  setTimeout(() => URL.revokeObjectURL(url), 30000);
}
