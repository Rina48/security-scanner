import { Component, type ReactNode } from "react";

interface Props {
  children: ReactNode;
}

interface State {
  hasError: boolean;
}

/**
 * React hata sınırı — alt bileşenlerde oluşan render hatalarını yakalar,
 * uygulamanın tamamen çökmesini önler ve fallback UI gösterir (CODING_STANDARDS 3.8).
 */
export class ErrorBoundary extends Component<Props, State> {
  constructor(props: Props) {
    super(props);
    this.state = { hasError: false };
  }

  static getDerivedStateFromError(): State {
    return { hasError: true };
  }

  render(): ReactNode {
    if (this.state.hasError) {
      return (
        <div
          style={{
            padding: "48px 24px",
            textAlign: "center",
            fontFamily: "inherit",
            color: "var(--text-primary)",
            backgroundColor: "var(--bg-page)",
            minHeight: "100vh",
            display: "flex",
            flexDirection: "column",
            alignItems: "center",
            justifyContent: "center",
            gap: "16px",
          }}
        >
          <p style={{ fontSize: "18px", margin: 0 }}>
            Beklenmeyen bir hata oluştu.
          </p>
          <p style={{ fontSize: "14px", color: "var(--text-secondary)", margin: 0 }}>
            Sayfayı yenileyerek tekrar deneyebilirsiniz.
          </p>
          <button
            type="button"
            onClick={() => window.location.reload()}
            style={{
              marginTop: "8px",
              padding: "12px 24px",
              fontSize: "16px",
              backgroundColor: "var(--accent)",
              color: "white",
              border: "none",
              borderRadius: "8px",
              cursor: "pointer",
            }}
          >
            Sayfayı Yenile
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}
