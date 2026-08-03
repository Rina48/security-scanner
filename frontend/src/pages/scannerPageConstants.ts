import type { ScanMode, Severity } from "../types";

export const MAX_HISTORY_ITEMS = 30;

export const RISK_BADGE_CLASS: Record<string, string> = {
  critical: "badge badge-critical",
  high: "badge badge-high",
  medium: "badge badge-medium",
  low: "badge badge-low",
  clean: "badge badge-clean",
};

export const SEVERITY_TR: Record<Severity, string> = {
  critical: "KRİTİK",
  high: "YÜKSEK",
  medium: "ORTA",
  low: "DÜŞÜK",
};

export const RISK_LEVEL_TR: Record<string, string> = {
  critical: "KRİTİK",
  high: "YÜKSEK",
  medium: "ORTA",
  low: "DÜŞÜK",
  clean: "TEMİZ",
};

export const CATEGORY_TR: Record<string, string> = {
  leak: "Sızıntı",
  headers: "Başlıklar",
  cookies: "Çerezler",
  tls: "TLS",
  active: "Aktif Test",
};

export const CONFIDENCE_TR: Record<string, string> = {
  high: "yüksek",
  medium: "orta",
  low: "düşük",
};

export const MODE_TR: Record<ScanMode, string> = {
  passive: "Pasif",
  active: "Aktif",
};
