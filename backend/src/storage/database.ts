import Database from "better-sqlite3";
import type { ScanResult } from "../types.js";

interface DbRow {
  scan_id: string;
  target_url: string;
  mode: "passive" | "active";
  active_allowed: number;
  score: number;
  started_at: string;
  completed_at: string;
  findings_json: string;
  executive_summary_json: string;
}

function rowToScanResult(row: DbRow): ScanResult {
  return {
    scanId: row.scan_id,
    targetUrl: row.target_url,
    mode: row.mode,
    isActiveAllowed: Boolean(row.active_allowed),
    score: row.score,
    startedAt: row.started_at,
    completedAt: row.completed_at,
    findings: JSON.parse(row.findings_json),
    executiveSummary: JSON.parse(row.executive_summary_json),
  };
}

const database = new Database("security-scanner.db");

database.exec(`
  CREATE TABLE IF NOT EXISTS scans (
    scan_id TEXT PRIMARY KEY,
    target_url TEXT NOT NULL,
    mode TEXT NOT NULL,
    active_allowed INTEGER NOT NULL,
    score INTEGER NOT NULL,
    started_at TEXT NOT NULL,
    completed_at TEXT NOT NULL,
    findings_json TEXT NOT NULL,
    executive_summary_json TEXT NOT NULL DEFAULT '{}'
  );
`);

// Migrate older databases that don't have the new column yet.
try {
  database.exec(
    `ALTER TABLE scans ADD COLUMN executive_summary_json TEXT NOT NULL DEFAULT '{}'`,
  );
} catch (err) {
  const msg = err instanceof Error ? err.message : String(err);
  if (!msg.includes("duplicate column")) {
    console.error("[database] Migration failed:", err);
  }
}

const insertScanStatement = database.prepare(`
  INSERT INTO scans (
    scan_id, target_url, mode, active_allowed, score,
    started_at, completed_at, findings_json, executive_summary_json
  ) VALUES (
    @scan_id, @target_url, @mode, @active_allowed, @score,
    @started_at, @completed_at, @findings_json, @executive_summary_json
  );
`);

const listScansStatement = database.prepare(`
  SELECT
    scan_id, target_url, mode, active_allowed, score,
    started_at, completed_at, findings_json, executive_summary_json
  FROM scans
  ORDER BY completed_at DESC
  LIMIT ?
`);

const getScanByIdStatement = database.prepare(`
  SELECT
    scan_id, target_url, mode, active_allowed, score,
    started_at, completed_at, findings_json, executive_summary_json
  FROM scans
  WHERE scan_id = ?
`);

export function saveScanResult(scanResult: ScanResult): void {
  insertScanStatement.run({
    scan_id: scanResult.scanId,
    target_url: scanResult.targetUrl,
    mode: scanResult.mode,
    active_allowed: scanResult.isActiveAllowed ? 1 : 0,
    score: scanResult.score,
    started_at: scanResult.startedAt,
    completed_at: scanResult.completedAt,
    findings_json: JSON.stringify(scanResult.findings),
    executive_summary_json: JSON.stringify(scanResult.executiveSummary),
  });
}

export function getScanResultById(scanId: string): ScanResult | null {
  const row = getScanByIdStatement.get(scanId) as DbRow | undefined;
  if (!row) return null;
  return rowToScanResult(row);
}

export function clearAllScanResults(): void {
  database.exec("DELETE FROM scans");
}

export function listRecentScanResults(limit = 20): ScanResult[] {
  const rows = listScansStatement.all(limit) as DbRow[];
  return rows.map(rowToScanResult);
}
