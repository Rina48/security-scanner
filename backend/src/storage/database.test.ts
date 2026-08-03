import assert from "node:assert/strict";
import test from "node:test";
import Database from "better-sqlite3";
import { Headers } from "undici";
import { runCookieScanner } from "../scanners/passive/cookieScanner.js";
import type { ScanResult } from "../types.js";
import { createScanResultStore } from "./database.js";

test("SQLite payload'ı hassas rapor alanlarını yazmadan cookie metadata'sını korur", () => {
  const database = new Database(":memory:");
  try {
    const store = createScanResultStore(database);
    const cookieName = "random_sqlite_cookie_8";
    const cookieSecret = "synthetic-sqlite-cookie-value-692";
    const querySecret = "synthetic-sqlite-query-value-703";
    const cookieFindings = runCookieScanner(
      new Headers({
        "set-cookie": `${cookieName}=${cookieSecret}; Secure; SameSite=Lax; Path=/private`,
      }),
      `https://example.test/path?token=${querySecret}`,
    );
    const cookieFinding = cookieFindings[0];
    assert.ok(cookieFinding);

    const report: ScanResult = {
      scanId: "synthetic-sqlite-scan",
      targetUrl: `https://example.test/path?api_key=${querySecret}&page=2`,
      mode: "passive",
      isActiveAllowed: false,
      score: 90,
      findings: [{
        ...cookieFinding,
        evidence: `${cookieFinding.evidence}\nsecret=${querySecret}`,
        remediation: `Rotate at https://example.test/help?password=${querySecret}`,
        endpoint: `https://example.test/path?access_token=${querySecret}`,
      }],
      executiveSummary: {
        riskLevel: "medium",
        headline: `Review https://example.test/path?session=${querySecret}`,
        businessRisk: `Set-Cookie: ${cookieName}=${cookieSecret}; Secure`,
        immediateActions: [`Authorization: Bearer ${querySecret}`],
        findingCounts: { critical: 0, high: 0, medium: 1, low: 0 },
      },
      startedAt: "2026-01-01T00:00:00.000Z",
      completedAt: "2026-01-01T00:00:01.000Z",
    };

    store.save(report);

    const row = database.prepare(`
      SELECT target_url, findings_json, executive_summary_json
      FROM scans WHERE scan_id = ?
    `).get(report.scanId);
    const rawPayload = JSON.stringify(row);
    assert.equal(rawPayload.includes(cookieSecret), false);
    assert.equal(rawPayload.includes(querySecret), false);
    assert.match(rawPayload, new RegExp(cookieName));
    assert.match(rawPayload, /Secure=present/);
    assert.match(rawPayload, /HttpOnly=missing/);
    assert.match(rawPayload, /SameSite=Lax/);
    assert.match(rawPayload, /page=2/);

    const historyResult = store.getById(report.scanId);
    assert.ok(historyResult);
    const apiHistoryPayload = JSON.stringify(historyResult);
    assert.equal(apiHistoryPayload.includes(cookieSecret), false);
    assert.equal(apiHistoryPayload.includes(querySecret), false);

    const legacyCookieSecret = "synthetic-legacy-cookie-value-147";
    const legacyQuerySecret = "synthetic-legacy-query-value-258";
    const legacyFindings = [{
      ...cookieFinding,
      evidence: `${cookieName}=${legacyCookieSecret}; Secure; SameSite=Strict; Path=/legacy`,
      endpoint: `https://example.test/legacy?session=${legacyQuerySecret}`,
    }];
    database.prepare(`
      UPDATE scans
      SET target_url = ?, findings_json = ?
      WHERE scan_id = ?
    `).run(
      `https://example.test/legacy?token=${legacyQuerySecret}`,
      JSON.stringify(legacyFindings),
      report.scanId,
    );

    createScanResultStore(database);
    const migratedRow = database.prepare(`
      SELECT target_url, findings_json, executive_summary_json
      FROM scans WHERE scan_id = ?
    `).get(report.scanId);
    const migratedPayload = JSON.stringify(migratedRow);
    assert.equal(migratedPayload.includes(legacyCookieSecret), false);
    assert.equal(migratedPayload.includes(legacyQuerySecret), false);
    assert.match(migratedPayload, new RegExp(cookieName));
    assert.match(migratedPayload, /Secure=present/);
    assert.match(migratedPayload, /HttpOnly=missing/);
    assert.match(migratedPayload, /SameSite=Strict/);
    assert.equal(migratedPayload.includes("Path=/legacy"), false);
  } finally {
    database.close();
  }
});
