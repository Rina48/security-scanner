export type ScanMode = "passive" | "active";

export type Severity = "critical" | "high" | "medium" | "low";

export interface ScannerFinding {
  id: string;
  category: "leak" | "headers" | "cookies" | "tls" | "active";
  title: string;
  severity: Severity;
  confidence: "high" | "medium" | "low";
  evidence: string;
  remediation: string;
  endpoint: string;
}

export interface ExecutiveSummary {
  riskLevel: "critical" | "high" | "medium" | "low" | "clean";
  headline: string;
  businessRisk: string;
  immediateActions: string[];
  findingCounts: { critical: number; high: number; medium: number; low: number };
}

export interface ScanRequest {
  targetUrl: string;
  mode: ScanMode;
  severityOverrides?: Record<string, Severity>;
  /** Varsayılan kimlik bilgisi denemesi — yalnızca aktif mod + izinli hedef için. Proxy ve delay kullanır. */
  credentialCheck?: boolean;
  /** Async modda önceden üretilmiş scanId — arka plan taraması için. */
  scanId?: string;
}

export interface ScanResult {
  scanId: string;
  targetUrl: string;
  mode: ScanMode;
  isActiveAllowed: boolean;
  score: number;
  findings: ScannerFinding[];
  executiveSummary: ExecutiveSummary;
  startedAt: string;
  completedAt: string;
}
