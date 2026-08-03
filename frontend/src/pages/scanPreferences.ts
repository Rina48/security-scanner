import type { ScanMode } from "../types";
import type { InputTab } from "./scannerPageTypes";

const STORAGE_KEY_PREFS = "security-scanner:prefs";
export const DEFAULT_TARGET_URL = "";

export interface ScanPreferences {
  targetUrl: string;
  mode: ScanMode;
  credentialCheck: boolean;
  inputTab: InputTab;
}

export function loadScanPreferences(): Partial<ScanPreferences> {
  try {
    const raw = localStorage.getItem(STORAGE_KEY_PREFS);
    if (!raw) return {};
    const parsed = JSON.parse(raw) as Record<string, unknown>;
    return {
      targetUrl:
        typeof parsed.targetUrl === "string" && parsed.targetUrl.startsWith("http")
          ? parsed.targetUrl
          : undefined,
      mode: parsed.mode === "passive" || parsed.mode === "active" ? parsed.mode : undefined,
      credentialCheck: typeof parsed.credentialCheck === "boolean" ? parsed.credentialCheck : undefined,
      inputTab: parsed.inputTab === "url" || parsed.inputTab === "body" ? parsed.inputTab : undefined,
    };
  } catch {
    return {};
  }
}

export function saveScanPreferences(prefs: ScanPreferences): void {
  try {
    localStorage.setItem(STORAGE_KEY_PREFS, JSON.stringify(prefs));
  } catch {
    // localStorage dolu veya gizli mod - sessizce gec.
  }
}
