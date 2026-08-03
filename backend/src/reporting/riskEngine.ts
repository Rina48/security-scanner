import type { ExecutiveSummary, ScannerFinding } from "../types.js";

const MAX_IMMEDIATE_ACTIONS = 5;

const SEVERITY_WEIGHT: Record<ScannerFinding["severity"], number> = {
  critical: 30,
  high: 18,
  medium: 10,
  low: 4,
};

export interface ScanSummary {
  score: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export function calculateRiskSummary(findings: ScannerFinding[]): ScanSummary {
  const critical = findings.filter((f) => f.severity === "critical").length;
  const high = findings.filter((f) => f.severity === "high").length;
  const medium = findings.filter((f) => f.severity === "medium").length;
  const low = findings.filter((f) => f.severity === "low").length;

  const totalWeight = findings.reduce(
    (total, finding) => total + SEVERITY_WEIGHT[finding.severity],
    0,
  );

  return { score: Math.max(0, 100 - totalWeight), critical, high, medium, low };
}

export function buildExecutiveSummary(
  targetUrl: string,
  findings: ScannerFinding[],
): ExecutiveSummary {
  const counts = calculateRiskSummary(findings);

  const riskLevel: ExecutiveSummary["riskLevel"] =
    counts.critical > 0
      ? "critical"
      : counts.high > 0
        ? "high"
        : counts.medium > 0
          ? "medium"
          : counts.low > 0
            ? "low"
            : "clean";

  const HEADLINE: Record<ExecutiveSummary["riskLevel"], string> = {
    critical: `${targetUrl} için kritik güvenlik açıkları tespit edildi — acil müdahale gerekiyor`,
    high: `${targetUrl} için yüksek öncelikli güvenlik sorunları tespit edildi`,
    medium: `${targetUrl} için orta düzeyli yapılandırma hataları tespit edildi`,
    low: `${targetUrl} için düşük öncelikli güvenlik iyileştirmeleri öneriliyor`,
    clean: `${targetUrl} tüm kontrolleri geçti, herhangi bir bulgu tespit edilmedi`,
  };

  const BUSINESS_RISK: Record<ExecutiveSummary["riskLevel"], string> = {
    critical:
      "Saldırgan, ifşa olan yapılandırma, sırlar veya hata ayıklama çıktısını kullanarak uygulama ve veriler üzerinde tam kontrol ele geçirebilir.",
    high: "Sunucu iç yapısının ve eski bileşenlerin açığa çıkması, hedefli saldırı için gereken çabayı önemli ölçüde azaltır.",
    medium:
      "Eksik güvenlik kontrolleri saldırı yüzeyini genişletir ve diğer zayıflıklarla birleştiğinde istismara yol açabilir.",
    low: "Tespit edilen sorunlar düşük anlık risk taşır ancak güçlü bir güvenlik temeli için ele alınmalıdır.",
    clean: "Bu taramada işlem yapılabilecek herhangi bir güvenlik bulgusu tespit edilmedi.",
  };

  const immediateActions: string[] = findings
    .filter((f) => f.severity === "critical" || f.severity === "high")
    .map((f) => f.remediation)
    .filter((value, index, array) => array.indexOf(value) === index)
    .slice(0, MAX_IMMEDIATE_ACTIONS);

  return {
    riskLevel,
    headline: HEADLINE[riskLevel],
    businessRisk: BUSINESS_RISK[riskLevel],
    immediateActions,
    findingCounts: {
      critical: counts.critical,
      high: counts.high,
      medium: counts.medium,
      low: counts.low,
    },
  };
}
