import type { FormEvent } from "react";
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
  apiToken: string;
  status: ConnectionStatus;
  tokenError: string;
  disabled: boolean;
  onApiTokenChange: (value: string) => void;
  onConnect: (event: FormEvent) => void;
  onDisconnect: () => void;
}

export function ConnectionPanel({
  apiToken,
  status,
  tokenError,
  disabled,
  onApiTokenChange,
  onConnect,
  onDisconnect,
}: ConnectionPanelProps) {
  const state = CONNECTION_COPY[status];
  const isConnected = status === "connected";
  const isConnecting = status === "connecting";

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
        <form className="connection-form" onSubmit={onConnect} noValidate>
          <label htmlFor="api-token">
            API token
            <input
              id="api-token"
              type="password"
              value={apiToken}
              onChange={(event) => onApiTokenChange(event.target.value)}
              autoComplete="off"
              placeholder="Tokenınızı girin"
              aria-invalid={Boolean(tokenError)}
              aria-describedby={tokenError ? "api-token-error api-token-help" : "api-token-help"}
              disabled={isConnecting}
            />
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
            type="submit"
            className="btn-connect"
            disabled={isConnecting}
          >
            {isConnecting ? "Bağlanıyor…" : "Bağlan"}
          </button>
        </form>
      )}
    </section>
  );
}
