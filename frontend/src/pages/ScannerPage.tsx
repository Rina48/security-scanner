import { useRef, useState } from "react";
import type { FormEvent } from "react";
import {
  analyzeBody,
  ApiClientError,
  clearScans,
  connectToApi,
  createScan,
  fetchScans,
} from "../apiClient";
import { BodyScanForm } from "../components/scanner/BodyScanForm";
import { ConfirmDialog } from "../components/scanner/ConfirmDialog";
import { ConnectionPanel } from "../components/scanner/ConnectionPanel";
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
import type {
  ConnectionStatus,
  HistoryStatus,
  InputTab,
  ScanStatus,
} from "./scannerPageTypes";
import { useConfirm } from "./useConfirm";
import { useTheme } from "./useTheme";
import { useToast } from "./useToast";

interface ScanFeedback {
  status: ScanStatus;
  title: string;
  description: string;
  nextAction?: string;
}

const IDLE_FEEDBACK: ScanFeedback = {
  status: "idle",
  title: "",
  description: "",
};

function validateTargetUrl(value: string): string {
  const trimmed = value.trim();
  if (!trimmed) return "Hedef URL gerekli. Tam HTTP veya HTTPS adresini girin.";
  try {
    const parsed = new URL(trimmed);
    if (!["http:", "https:"].includes(parsed.protocol) || !parsed.hostname) {
      return "HTTP veya HTTPS ile başlayan geçerli bir hedef URL girin.";
    }
    if (parsed.username || parsed.password) {
      return "Kimlik bilgisi içermeyen bir hedef URL girin.";
    }
    return "";
  } catch {
    return "HTTP veya HTTPS ile başlayan geçerli bir hedef URL girin.";
  }
}

function feedbackForError(error: unknown): ScanFeedback {
  if (error instanceof ApiClientError) {
    switch (error.code) {
      case "api-unreachable":
        return {
          status: "error",
          title: "API erişilemiyor",
          description: "Tarama servisiyle bağlantı kurulamadı.",
          nextAction: "API servisinin çalıştığını kontrol edip yeniden bağlanın.",
        };
      case "invalid-token":
        return {
          status: "error",
          title: "Token kabul edilmedi",
          description: "API bağlantısı artık kullanılamıyor.",
          nextAction: "Tokenı kontrol edip yeniden bağlanın.",
        };
      case "target-not-authorized":
        return {
          status: "error",
          title: "Aktif tarama yetkili değil",
          description: "Bu hedef sunucunun aktif tarama izin listesinde değil.",
          nextAction: "İzinli bir local/lab hedefi seçin veya pasif tarama kullanın.",
        };
      case "invalid-request":
        return {
          status: "error",
          title: "Tarama bilgileri geçersiz",
          description: "İstek API tarafından kabul edilmedi.",
          nextAction: "Hedef ve tarama seçeneklerini kontrol edip yeniden deneyin.",
        };
      case "resource-limited":
        return {
          status: "error",
          title: "Tarama kapasitesi dolu",
          description: "Sunucu yeni bir taramayı şu anda kabul edemiyor.",
          nextAction: "Kısa bir süre bekleyip yeniden deneyin.",
        };
      case "request-failed":
        return {
          status: "error",
          title: "Tarama başarısız oldu",
          description: "API taramayı tamamlayamadı.",
          nextAction: "Bir süre sonra aynı taramayı yeniden deneyin.",
        };
      default:
        break;
    }
  }

  return {
    status: "error",
    title: "Beklenmeyen hata",
    description: "İşlem beklenmeyen bir nedenle tamamlanamadı.",
    nextAction: "Sayfayı yenileyip yeniden deneyin.",
  };
}

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
  const [connectedToken, setConnectedToken] = useState("");
  const [connectionStatus, setConnectionStatus] =
    useState<ConnectionStatus>("disconnected");
  const [tokenError, setTokenError] = useState("");
  const [isRunning, setIsRunning] = useState(false);
  const [urlError, setUrlError] = useState("");
  const [scanFeedback, setScanFeedback] = useState<ScanFeedback>(IDLE_FEEDBACK);
  const [latestScan, setLatestScan] = useState<ScanResult | null>(null);
  const [history, setHistory] = useState<ScanResult[]>([]);
  const [historyStatus, setHistoryStatus] = useState<HistoryStatus>("idle");
  const [historyError, setHistoryError] = useState("");
  const operationController = useRef<AbortController | null>(null);

  const isConnected = connectionStatus === "connected" && Boolean(connectedToken);

  function persistPreferences(next: {
    targetUrl?: string;
    mode?: ScanMode;
    credentialCheck?: boolean;
    inputTab?: InputTab;
  }): void {
    saveScanPreferences({
      targetUrl: next.targetUrl ?? targetUrl,
      mode: next.mode ?? mode,
      credentialCheck: next.credentialCheck ?? credentialCheck,
      inputTab: next.inputTab ?? inputTab,
    });
  }

  function updateInputTab(nextTab: InputTab): void {
    setInputTab(nextTab);
    persistPreferences({ inputTab: nextTab });
    setScanFeedback(IDLE_FEEDBACK);
  }

  function updateTargetUrl(value: string): void {
    setTargetUrl(value);
    setUrlError("");
    persistPreferences({ targetUrl: value });
  }

  function updateMode(nextMode: ScanMode): void {
    setMode(nextMode);
    persistPreferences({ mode: nextMode });
  }

  function updateCredentialCheck(value: boolean): void {
    setCredentialCheck(value);
    persistPreferences({ credentialCheck: value });
  }

  async function handleConnect(): Promise<void> {
    if (connectionStatus === "connecting" || isRunning) return;

    const token = apiToken.trim();
    if (!token) {
      setTokenError("API token gerekli. Tokenı girip Bağlan’ı seçin.");
      setConnectionStatus("disconnected");
      return;
    }

    setTokenError("");
    setConnectionStatus("connecting");
    setHistoryStatus("loading");
    setHistoryError("");

    try {
      const scans = await connectToApi(token);
      setConnectedToken(token);
      setApiToken("");
      setConnectionStatus("connected");
      setHistory(scans.slice(0, MAX_HISTORY_ITEMS));
      setHistoryStatus("ready");
      setScanFeedback(IDLE_FEEDBACK);
    } catch (error) {
      setConnectedToken("");
      setHistory([]);
      setHistoryStatus("idle");
      if (error instanceof ApiClientError && error.code === "invalid-token") {
        setConnectionStatus("invalid-token");
        setTokenError("Token kabul edilmedi. Tokenı kontrol edip yeniden deneyin.");
      } else {
        setConnectionStatus("unreachable");
        setTokenError("API servisine ulaşılamadı. Servisi kontrol edip yeniden deneyin.");
      }
    }
  }

  function disconnect(): void {
    setConnectedToken("");
    setApiToken("");
    setConnectionStatus("disconnected");
    setTokenError("");
    setHistory([]);
    setHistoryStatus("idle");
    setHistoryError("");
    setLatestScan(null);
    setScanFeedback(IDLE_FEEDBACK);
  }

  async function loadHistory(): Promise<void> {
    if (!connectedToken || connectionStatus !== "connected") return;
    setHistoryStatus("loading");
    setHistoryError("");
    try {
      const scans = await fetchScans(connectedToken);
      setHistory(scans.slice(0, MAX_HISTORY_ITEMS));
      setHistoryStatus("ready");
    } catch (error) {
      const feedback = feedbackForError(error);
      if (error instanceof ApiClientError && error.code === "invalid-token") {
        setConnectedToken("");
        setConnectionStatus("invalid-token");
        setHistory([]);
        setLatestScan(null);
        setHistoryStatus("idle");
        setHistoryError("");
        return;
      }
      if (error instanceof ApiClientError && error.code === "api-unreachable") {
        setConnectedToken("");
        setConnectionStatus("unreachable");
        setHistory([]);
        setLatestScan(null);
        setHistoryStatus("idle");
        setHistoryError("");
        return;
      }
      setHistoryStatus("error");
      setHistoryError(feedback.nextAction ?? feedback.description);
    }
  }

  function recordScan(result: ScanResult): void {
    setLatestScan(result);
    setHistoryStatus("ready");
    setHistory((previous) => [
      result,
      ...previous.filter((scan) => scan.scanId !== result.scanId),
    ].slice(0, MAX_HISTORY_ITEMS));
  }

  function selectScan(scan: ScanResult): void {
    setLatestScan(scan);
    window.scrollTo({ top: 0, behavior: "smooth" });
  }

  async function runOperation(
    operation: (signal: AbortSignal) => Promise<ScanResult>,
    runningDescription: string,
  ): Promise<void> {
    if (operationController.current || !connectedToken) return;

    const controller = new AbortController();
    operationController.current = controller;
    setIsRunning(true);
    setScanFeedback({
      status: "running",
      title: "Tarama sürüyor",
      description: runningDescription,
    });

    try {
      const result = await operation(controller.signal);
      if (controller.signal.aborted) return;
      recordScan(result);
      setScanFeedback({
        status: "completed",
        title: "Tarama tamamlandı",
        description: `${result.findings.length} bulgu rapora işlendi.`,
        nextAction: "Öncelikli bulguyu ve önerilen ilk adımları inceleyin.",
      });
    } catch (error) {
      if (error instanceof DOMException && error.name === "AbortError") {
        setScanFeedback({
          status: "cancelled",
          title: "Tarama iptal edildi",
          description: "İptal edilen URL taraması sonuç veya hata olarak gösterilmedi.",
          nextAction: "Hazır olduğunuzda taramayı yeniden başlatın.",
        });
      } else {
        const feedback = feedbackForError(error);
        setScanFeedback(feedback);
        if (error instanceof ApiClientError && error.code === "invalid-token") {
          setConnectedToken("");
          setConnectionStatus("invalid-token");
          setHistory([]);
          setLatestScan(null);
          setHistoryStatus("idle");
        }
        if (error instanceof ApiClientError && error.code === "api-unreachable") {
          setConnectedToken("");
          setConnectionStatus("unreachable");
          setHistory([]);
          setLatestScan(null);
          setHistoryStatus("idle");
        }
      }
    } finally {
      if (operationController.current === controller) operationController.current = null;
      setIsRunning(false);
    }
  }

  async function handleUrlSubmit(event: FormEvent): Promise<void> {
    event.preventDefault();
    if (operationController.current) return;
    if (!isConnected) {
      setScanFeedback({
        status: "error",
        title: "API bağlantısı gerekli",
        description: "Tarama bağlantı kurulmadan başlatılamaz.",
        nextAction: "API tokenınızı girip Bağlan’ı seçin.",
      });
      return;
    }

    const validationError = validateTargetUrl(targetUrl);
    setUrlError(validationError);
    if (validationError) {
      setScanFeedback({
        status: "error",
        title: "Hedef URL geçersiz",
        description: validationError,
        nextAction: "URL’yi düzeltip taramayı yeniden başlatın.",
      });
      return;
    }

    await runOperation(
      (signal) =>
        createScan(connectedToken, targetUrl.trim(), mode, {
          credentialCheck: mode === "active" ? credentialCheck : undefined,
          signal,
        }),
      mode === "active"
        ? "İzinli hedef üzerinde aktif kontroller çalıştırılıyor."
        : "Hedef yanıtı ve pasif güvenlik sinyalleri inceleniyor.",
    );
  }

  async function handleBodySubmit(event: FormEvent): Promise<void> {
    event.preventDefault();
    if (operationController.current) return;
    if (!isConnected) {
      setScanFeedback({
        status: "error",
        title: "API bağlantısı gerekli",
        description: "Yanıt analizi bağlantı kurulmadan başlatılamaz.",
        nextAction: "API tokenınızı girip Bağlan’ı seçin.",
      });
      return;
    }
    if (!pasteBody.trim()) {
      setScanFeedback({
        status: "error",
        title: "Yanıt gövdesi gerekli",
        description: "Analiz edilecek içerik boş olamaz.",
        nextAction: "Yanıt gövdesini yapıştırıp yeniden deneyin.",
      });
      return;
    }

    await runOperation(
      (signal) =>
        analyzeBody(
          connectedToken,
          pasteLabel.trim() || "yapistirilan-yanit",
          pasteBody,
          signal,
        ),
      "Yapıştırılan yanıt ağ isteği gönderilmeden analiz ediliyor.",
    );
  }

  function cancelOperation(): void {
    const controller = operationController.current;
    if (!controller || controller.signal.aborted) return;
    controller.abort();
    setScanFeedback({
      status: "cancelled",
      title: "Tarama iptal ediliyor",
      description: "İstek durduruluyor; tamamlanmış bir sonuç gösterilmeyecek.",
    });
  }

  return (
    <main className="page">
      <header className="app-header">
        <div>
          <p className="eyebrow">Yerel güvenlik incelemesi</p>
          <h1>Security Scanner</h1>
          <p>Savunma amaçlı taramaları başlatın, durumu izleyin ve öncelikli bulgulara odaklanın.</p>
        </div>
        <button
          type="button"
          className="btn-theme"
          onClick={toggleTheme}
          aria-label={theme === "dark" ? "Açık temaya geç" : "Koyu temaya geç"}
          aria-pressed={theme === "dark"}
        >
          {theme === "dark" ? "Açık tema" : "Koyu tema"}
        </button>
      </header>

      <ConnectionPanel
        status={connectionStatus}
        tokenError={tokenError}
        disabled={isRunning}
        onApiTokenChange={(value) => {
          setApiToken(value);
          setTokenError("");
          if (connectionStatus === "invalid-token" || connectionStatus === "unreachable") {
            setConnectionStatus("disconnected");
          }
        }}
        onConnect={handleConnect}
        onDisconnect={disconnect}
      />

      <section className="scanner-section" aria-labelledby="scanner-title">
        <div className="section-heading scanner-heading">
          <div>
            <p className="eyebrow">Yeni inceleme</p>
            <h2 id="scanner-title">Ne analiz etmek istiyorsunuz?</h2>
          </div>
        </div>

        <div className="input-tabs" role="tablist" aria-label="Analiz kaynağı">
          <button
            type="button"
            role="tab"
            id="url-tab"
            aria-controls="url-panel"
            aria-selected={inputTab === "url"}
            className={inputTab === "url" ? "input-tab input-tab-active" : "input-tab"}
            onClick={() => updateInputTab("url")}
            disabled={isRunning}
          >
            URL tara
            <span>Canlı hedef yanıtını incele</span>
          </button>
          <button
            type="button"
            role="tab"
            id="body-tab"
            aria-controls="body-panel"
            aria-selected={inputTab === "body"}
            className={inputTab === "body" ? "input-tab input-tab-active" : "input-tab"}
            onClick={() => updateInputTab("body")}
            disabled={isRunning}
          >
            Yanıt gövdesi analiz et
            <span>Kaydedilmiş içeriği çevrimdışı tara</span>
          </button>
        </div>

        <div
          id={inputTab === "url" ? "url-panel" : "body-panel"}
          role="tabpanel"
          aria-labelledby={inputTab === "url" ? "url-tab" : "body-tab"}
        >
          {inputTab === "url" ? (
            <UrlScanForm
              targetUrl={targetUrl}
              mode={mode}
              credentialCheck={credentialCheck}
              isRunning={isRunning}
              isConnected={isConnected}
              urlError={urlError}
              onTargetUrlChange={updateTargetUrl}
              onTargetUrlBlur={() => {
                if (targetUrl.trim()) setUrlError(validateTargetUrl(targetUrl));
              }}
              onModeChange={updateMode}
              onCredentialCheckChange={updateCredentialCheck}
              onSubmit={handleUrlSubmit}
            />
          ) : (
            <BodyScanForm
              pasteLabel={pasteLabel}
              pasteBody={pasteBody}
              isRunning={isRunning}
              isConnected={isConnected}
              onPasteLabelChange={setPasteLabel}
              onPasteBodyChange={setPasteBody}
              onSubmit={handleBodySubmit}
              onClear={() => {
                setPasteBody("");
                setPasteLabel("");
              }}
            />
          )}
        </div>

        <ScanStatusPanel
          feedback={scanFeedback}
          canCancel={isRunning && scanFeedback.status === "running" && inputTab === "url"}
          onCancel={cancelOperation}
        />
      </section>

      {latestScan ? (
        <ScanReportCard key={latestScan.scanId} scan={latestScan} onToast={showToast} />
      ) : null}

      <ScanHistoryCard
        history={history}
        status={historyStatus}
        errorMessage={historyError}
        onRetry={() => void loadHistory()}
        onClearHistory={() => {
          showConfirm("Tüm tarama geçmişi silinecek. Bu işlem geri alınamaz.", async () => {
            try {
              await clearScans(connectedToken);
              setHistory([]);
              setHistoryStatus("ready");
              showToast("Tarama geçmişi temizlendi.");
            } catch {
              setHistoryStatus("error");
              setHistoryError("API bağlantısını kontrol edip yeniden deneyin.");
              showToast("Geçmiş temizlenemedi. Bağlantıyı kontrol edin.");
            }
          });
        }}
        onSelectScan={selectScan}
      />

      {toastMessage ? (
        <div className="toast" role="status" aria-live="polite">
          {toastMessage}
        </div>
      ) : null}

      {confirmState ? <ConfirmDialog confirmState={confirmState} onCancel={closeConfirm} /> : null}
    </main>
  );
}

function ScanStatusPanel({
  feedback,
  canCancel,
  onCancel,
}: {
  feedback: ScanFeedback;
  canCancel: boolean;
  onCancel: () => void;
}) {
  if (feedback.status === "idle") return null;
  const isError = feedback.status === "error";

  return (
    <div
      className={`scan-status scan-status-${feedback.status}`}
      role={isError ? "alert" : "status"}
      aria-live={isError ? "assertive" : "polite"}
      aria-busy={feedback.status === "running"}
    >
      <span className="scan-status-mark" aria-hidden="true" />
      <div className="scan-status-copy">
        <strong>{feedback.title}</strong>
        <p>{feedback.description}</p>
        {feedback.nextAction ? <p className="next-action">Sonraki adım: {feedback.nextAction}</p> : null}
      </div>
      {canCancel ? (
        <button type="button" className="btn-cancel" onClick={onCancel}>
          Taramayı iptal et
        </button>
      ) : null}
    </div>
  );
}
