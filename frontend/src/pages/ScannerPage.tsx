import { useEffect, useState } from "react";
import type { FormEvent } from "react";
import { analyzeBody, clearScans, createScan, fetchScans } from "../apiClient";
import { BodyScanForm } from "../components/scanner/BodyScanForm";
import { ConfirmDialog } from "../components/scanner/ConfirmDialog";
import { ScanHistoryCard } from "../components/scanner/ScanHistoryCard";
import { ScanReportCard } from "../components/scanner/ScanReportCard";
import { UrlScanForm } from "../components/scanner/UrlScanForm";
import type { ScanMode, ScanResult } from "../types";
import {
  DEFAULT_TARGET_URL,
  loadScanPreferences,
  saveScanPreferences,
} from "./scanPreferences";
import { MAX_HISTORY_ITEMS } from "./scannerPageConstants";
import type { ActiveTab, InputTab } from "./scannerPageTypes";
import { useConfirm } from "./useConfirm";
import { useTheme } from "./useTheme";
import { useToast } from "./useToast";

export function ScannerPage() {
  const { theme, toggleTheme } = useTheme();
  const { toastMessage, showToast } = useToast();
  const { confirmState, showConfirm, closeConfirm } = useConfirm();

  const [initialPrefs] = useState(loadScanPreferences);
  const [inputTab, setInputTab] = useState<InputTab>(() => initialPrefs.inputTab ?? "url");
  const [targetUrl, setTargetUrl] = useState(() => initialPrefs.targetUrl ?? DEFAULT_TARGET_URL);
  const [mode, setMode] = useState<ScanMode>(() => initialPrefs.mode ?? "passive");
  const [credentialCheck, setCredentialCheck] = useState(
    () => initialPrefs.credentialCheck ?? false,
  );
  const [pasteLabel, setPasteLabel] = useState("");
  const [pasteBody, setPasteBody] = useState("");
  const [apiToken, setApiToken] = useState("");
  const [isRunning, setIsRunning] = useState(false);
  const [errorMessage, setErrorMessage] = useState("");
  const [activeTab, setActiveTab] = useState<ActiveTab>("executive");
  const [latestScan, setLatestScan] = useState<ScanResult | null>(null);
  const [history, setHistory] = useState<ScanResult[]>([]);

  useEffect(() => {
    if (!apiToken) {
      setHistory([]);
      return;
    }
    fetchScans(apiToken).then(setHistory).catch(() => setHistory([]));
  }, [apiToken]);

  useEffect(() => {
    saveScanPreferences({ targetUrl, mode, credentialCheck, inputTab });
  }, [targetUrl, mode, credentialCheck, inputTab]);

  function recordScan(result: ScanResult): void {
    setLatestScan(result);
    setActiveTab("executive");
    setHistory((prev) => [result, ...prev].slice(0, MAX_HISTORY_ITEMS));
  }

  function selectScan(scan: ScanResult): void {
    setLatestScan(scan);
    setActiveTab("executive");
    window.scrollTo({ top: 0, behavior: "smooth" });
  }

  async function handleUrlSubmit(event: FormEvent) {
    event.preventDefault();
    setIsRunning(true);
    setErrorMessage("");
    try {
      const result = await createScan(apiToken, targetUrl, mode, {
        credentialCheck: mode === "active" ? credentialCheck : undefined,
      });
      recordScan(result);
    } catch (error) {
      const message =
        error instanceof Error ? error.message : "Tarama sırasında bilinmeyen bir hata oluştu.";
      setErrorMessage(message);
    } finally {
      setIsRunning(false);
    }
  }

  async function handleBodySubmit(event: FormEvent) {
    event.preventDefault();
    if (!pasteBody.trim()) return;
    setIsRunning(true);
    setErrorMessage("");
    try {
      const label = pasteLabel.trim() || "yapistirilan-yanit";
      const result = await analyzeBody(apiToken, label, pasteBody);
      recordScan(result);
    } catch (error) {
      const message =
        error instanceof Error ? error.message : "Analiz sırasında bilinmeyen bir hata oluştu.";
      setErrorMessage(message);
    } finally {
      setIsRunning(false);
    }
  }

  function clearBody(): void {
    setPasteBody("");
    setPasteLabel("");
  }

  return (
    <main className="page">
      <section className="card">
        <div className="top-bar">
          <h1>Güvenlik Tarayıcı</h1>
          <button
            type="button"
            className="btn-theme"
            onClick={toggleTheme}
            title={theme === "dark" ? "Açık moda geç" : "Karanlık moda geç"}
            aria-label={theme === "dark" ? "Açık moda geç" : "Karanlık moda geç"}
          >
            {theme === "dark" ? "☀️" : "🌙"}
          </button>
        </div>

        <label className="api-token-field" htmlFor="api-token">
          API token
          <input
            id="api-token"
            type="password"
            value={apiToken}
            onChange={(event) => setApiToken(event.target.value)}
            autoComplete="off"
            placeholder="SECURITY_SCANNER_API_TOKEN"
          />
        </label>

        <div className="input-tabs">
          <button
            type="button"
            className={inputTab === "url" ? "input-tab input-tab-active" : "input-tab"}
            onClick={() => setInputTab("url")}
          >
            URL Tara
          </button>
          <button
            type="button"
            className={inputTab === "body" ? "input-tab input-tab-active" : "input-tab"}
            onClick={() => setInputTab("body")}
          >
            Yanıt Yapıştır
          </button>
        </div>

        {inputTab === "url" ? (
          <UrlScanForm
            targetUrl={targetUrl}
            mode={mode}
            credentialCheck={credentialCheck}
            isRunning={isRunning}
            onTargetUrlChange={setTargetUrl}
            onModeChange={setMode}
            onCredentialCheckChange={setCredentialCheck}
            onSubmit={handleUrlSubmit}
          />
        ) : (
          <BodyScanForm
            pasteLabel={pasteLabel}
            pasteBody={pasteBody}
            isRunning={isRunning}
            onPasteLabelChange={setPasteLabel}
            onPasteBodyChange={setPasteBody}
            onSubmit={handleBodySubmit}
            onClear={clearBody}
          />
        )}

        {errorMessage ? <p className="error">{errorMessage}</p> : null}
      </section>

      {latestScan ? (
        <ScanReportCard
          activeTab={activeTab}
          scan={latestScan}
          onActiveTabChange={setActiveTab}
          onToast={showToast}
        />
      ) : null}

      <ScanHistoryCard
        history={history}
        onClearHistory={() => {
          showConfirm("Tüm tarama geçmişi silinecek. Emin misiniz?", async () => {
            await clearScans(apiToken);
            setHistory([]);
          });
        }}
        onSelectScan={selectScan}
      />

      {toastMessage ? (
        <div className="toast" role="status" aria-live="polite">
          {toastMessage}
        </div>
      ) : null}

      {confirmState ? (
        <ConfirmDialog confirmState={confirmState} onCancel={closeConfirm} />
      ) : null}
    </main>
  );
}
