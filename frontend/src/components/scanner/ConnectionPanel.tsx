import { useState } from "react";
import type { KeyboardEvent } from "react";
import type { ConnectionStatus } from "../../pages/scannerPageTypes";

const CONNECTION_COPY: Record<
  ConnectionStatus,
  { label: string; description: string; tone: string }
> = {
  disconnected: {
    label: "Bağlı değil",
    description: "Tarama ve geçmiş için API bağlantısı kurun.",
    tone: "neutral",
  },
  connecting: {
    label: "Bağlanıyor",
    description: "Token doğrulanıyor ve geçmiş yükleniyor.",
    tone: "progress",
  },
  connected: {
    label: "Bağlı",
    description: "API hazır. Tarama ve geçmiş işlemlerini kullanabilirsiniz.",
    tone: "success",
  },
  "invalid-token": {
    label: "Token geçersiz",
    description: "Tokenı kontrol edip yeniden bağlanın.",
    tone: "danger",
  },
  unreachable: {
    label: "API erişilemiyor",
    description: "API servisinin çalıştığını kontrol edip yeniden deneyin.",
    tone: "danger",
  },
};

interface ConnectionPanelProps {
  status: ConnectionStatus;
  tokenError: string;
  disabled: boolean;
  onApiTokenChange: (value: string) => void;
  onConnect: () => void;
  onDisconnect: () => void;
}

export function ConnectionPanel({
  status,
  tokenError,
  disabled,
  onApiTokenChange,
  onConnect,
  onDisconnect,
}: ConnectionPanelProps) {
  const [isTokenVisible, setIsTokenVisible] = useState(false);
  const state = CONNECTION_COPY[status];
  const isConnected = status === "connected";
  const isConnecting = status === "connecting";

  function connect(): void {
    setIsTokenVisible(false);
    onConnect();
  }

  return (
    <section className="connection-panel" aria-labelledby="connection-title">
      <div className="section-heading connection-heading">
        <div>
          <p className="eyebrow">Bağlantı</p>
          <h2 id="connection-title">API erişimi</h2>
        </div>
        <div className={`status-pill status-pill-${state.tone}`} role="status">
          <span className="status-indicator" aria-hidden="true" />
          {state.label}
        </div>
      </div>

      <p className="section-description">{state.description}</p>

      {isConnected ? (
        <div className="connection-actions connection-actions-connected">
          <p className="privacy-note">Token yalnızca bu sekmenin belleğinde tutulur.</p>
          <button
            type="button"
            className="btn-secondary"
            onClick={onDisconnect}
            disabled={disabled}
          >
            Bağlantıyı kes
          </button>
        </div>
      ) : (
        <div className="connection-form">
          <label htmlFor="api-token">
            API token
            <span className="token-input-control">
              <input
                id="api-token"
                className={isTokenVisible ? "token-input" : "token-input token-input-masked"}
                type="text"
                onChange={(event) => onApiTokenChange(event.target.value)}
                onKeyDown={(event: KeyboardEvent<HTMLInputElement>) => {
                  if (event.key !== "Enter" || isConnecting) return;
                  event.preventDefault();
                  connect();
                }}
                autoComplete="off"
                autoCapitalize="none"
                spellCheck={false}
                placeholder="Tokenınızı girin"
                aria-invalid={Boolean(tokenError)}
                aria-describedby={tokenError ? "api-token-error api-token-help" : "api-token-help"}
                disabled={isConnecting}
              />
              <button
                type="button"
                className="btn-token-visibility"
                onClick={() => setIsTokenVisible((visible) => !visible)}
                aria-label={isTokenVisible ? "API tokenını gizle" : "API tokenını göster"}
                aria-pressed={isTokenVisible}
                disabled={isConnecting}
              >
                {isTokenVisible ? "Gizle" : "Göster"}
              </button>
            </span>
          </label>
          <p id="api-token-help" className="field-help">
            Token tarayıcı depolamasına yazılmaz ve bağlantıdan sonra alanda gösterilmez.
          </p>
          {tokenError ? (
            <p id="api-token-error" className="field-error" role="alert">
              {tokenError}
            </p>
          ) : null}
          <button
            type="button"
            className="btn-connect"
            onClick={connect}
            disabled={isConnecting}
          >
            {isConnecting ? "Bağlanıyor…" : "Bağlan"}
          </button>
        </div>
      )}
    </section>
  );
}
