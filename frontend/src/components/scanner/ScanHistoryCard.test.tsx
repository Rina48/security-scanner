import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ComponentProps } from "react";
import { describe, expect, it, vi } from "vitest";
import { createScanResult } from "../../test/fixtures";
import { ScanHistoryCard } from "./ScanHistoryCard";

function renderHistory(overrides: Partial<ComponentProps<typeof ScanHistoryCard>> = {}) {
  const props: ComponentProps<typeof ScanHistoryCard> = {
    history: [],
    status: "ready",
    errorMessage: "",
    onClearHistory: vi.fn(),
    onRetry: vi.fn(),
    onSelectScan: vi.fn(),
    ...overrides,
  };

  return { ...render(<ScanHistoryCard {...props} />), props };
}

describe("ScanHistoryCard", () => {
  it("boş geçmiş durumunu gösterir", () => {
    renderHistory();

    expect(screen.getByText("Henüz tarama kaydı yok")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Geçmişi temizle" })).not.toBeInTheDocument();
  });

  it("yüklenme durumunu canlı durum mesajıyla gösterir", () => {
    renderHistory({ status: "loading" });

    expect(screen.getByRole("status")).toHaveTextContent("Geçmiş yükleniyor");
    expect(screen.queryByText("Henüz tarama kaydı yok")).not.toBeInTheDocument();
  });

  it("hata durumunu yeniden deneme eylemiyle gösterir", async () => {
    const user = userEvent.setup();
    const onRetry = vi.fn();
    renderHistory({
      status: "error",
      errorMessage: "Bağlantıyı kontrol edip yeniden deneyin.",
      onRetry,
    });

    expect(screen.getByRole("alert")).toHaveTextContent("Geçmiş yüklenemedi");
    await user.click(screen.getByRole("button", { name: "Yeniden dene" }));
    expect(onRetry).toHaveBeenCalledOnce();
  });

  it("dolu geçmiş durumunda kayıtları ve risk bilgisini gösterir", () => {
    const scan = createScanResult({
      targetUrl: "https://history.example.test",
      executiveSummary: {
        riskLevel: "high",
        headline: "Yüksek risk",
        businessRisk: "Kontrollü test riski.",
        immediateActions: [],
        findingCounts: { critical: 0, high: 1, medium: 0, low: 0 },
      },
    });
    renderHistory({ history: [scan] });

    const historyButton = screen.getByRole("button", {
      name: "https://history.example.test raporunu aç",
    });
    expect(within(historyButton).getByText("YÜKSEK")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Geçmişi temizle" })).toBeInTheDocument();
  });
});
