import Database from "better-sqlite3";
import type { ScanResult } from "../types.js";
import { redactScanResult } from "../utils/reportRedaction.js";
import { logRedactedError } from "../utils/safeLogging.js";

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

export interface ScanResultStore {
  save(scanResult: ScanResult): void;
  getById(scanId: string): ScanResult | null;
  clearAll(): void;
  listRecent(limit?: number): ScanResult[];
}

function rowToScanResult(row: DbRow): ScanResult {
  return redactScanResult({
    scanId: row.scan_id,
    targetUrl: row.target_url,
    mode: row.mode,
    isActiveAllowed: Boolean(row.active_allowed),
    score: row.score,
    startedAt: row.started_at,
    completedAt: row.completed_at,
    findings: JSON.parse(row.findings_json),
    executiveSummary: JSON.parse(row.executive_summary_json),
  });
}

function initializeDatabase(database: Database.Database): void {
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
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    if (!message.includes("duplicate column")) {
      logRedactedError("[database] Migration failed:", error);
      throw new Error("Database migration failed.");
    }
  }
}

export function createScanResultStore(database: Database.Database): ScanResultStore {
  initializeDatabase(database);

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

  const listAllScansStatement = database.prepare(`
    SELECT
      scan_id, target_url, mode, active_allowed, score,
      started_at, completed_at, findings_json, executive_summary_json
    FROM scans
  `);

  const updateRedactedPayloadStatement = database.prepare(`
    UPDATE scans
    SET target_url = @target_url,
        findings_json = @findings_json,
        executive_summary_json = @executive_summary_json
    WHERE scan_id = @scan_id
  `);

  const redactStoredPayloads = database.transaction(() => {
    const rows = listAllScansStatement.all() as DbRow[];
    for (const row of rows) {
      const redacted = rowToScanResult(row);
      const findingsJson = JSON.stringify(redacted.findings);
      const executiveSummaryJson = JSON.stringify(redacted.executiveSummary);
      if (
        redacted.targetUrl === row.target_url
        && findingsJson === row.findings_json
        && executiveSummaryJson === row.executive_summary_json
      ) {
        continue;
      }
      updateRedactedPayloadStatement.run({
        scan_id: row.scan_id,
        target_url: redacted.targetUrl,
        findings_json: findingsJson,
        executive_summary_json: executiveSummaryJson,
      });
    }
  });

  try {
    redactStoredPayloads();
  } catch (error) {
    logRedactedError("[database] Stored scan redaction failed:", error);
    throw new Error("Stored scan redaction failed.");
  }

  return {
    save(scanResult) {
      const redacted = redactScanResult(scanResult);
      insertScanStatement.run({
        scan_id: redacted.scanId,
        target_url: redacted.targetUrl,
        mode: redacted.mode,
        active_allowed: redacted.isActiveAllowed ? 1 : 0,
        score: redacted.score,
        started_at: redacted.startedAt,
        completed_at: redacted.completedAt,
        findings_json: JSON.stringify(redacted.findings),
        executive_summary_json: JSON.stringify(redacted.executiveSummary),
      });
    },

    getById(scanId) {
      const row = getScanByIdStatement.get(scanId) as DbRow | undefined;
      return row ? rowToScanResult(row) : null;
    },

    clearAll() {
      database.exec("DELETE FROM scans");
    },

    listRecent(limit = 20) {
      const rows = listScansStatement.all(limit) as DbRow[];
      return rows.map(rowToScanResult);
    },
  };
}

const databasePath = process.env.SECURITY_SCANNER_DB_PATH || "security-scanner.db";
const defaultStore = createScanResultStore(new Database(databasePath));

export function saveScanResult(scanResult: ScanResult): void {
  defaultStore.save(scanResult);
}

export function getScanResultById(scanId: string): ScanResult | null {
  return defaultStore.getById(scanId);
}

export function clearAllScanResults(): void {
  defaultStore.clearAll();
}

export function listRecentScanResults(limit = 20): ScanResult[] {
  return defaultStore.listRecent(limit);
}
