import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { createFinding, createScanResult } from "../../test/fixtures";
import { ScanReportCard } from "./ScanReportCard";

describe("ScanReportCard", () => {
  it("bulguları önem sırasına göre gösterir", () => {
    const scan = createScanResult({
      findings: [
        createFinding("low", "Düşük bulgu"),
        createFinding("critical", "Kritik bulgu"),
        createFinding("medium", "Orta bulgu"),
        createFinding("high", "Yüksek bulgu"),
      ],
    });

    render(<ScanReportCard scan={scan} onToast={vi.fn()} />);

    expect(screen.getAllByRole("heading", { level: 4 }).map((heading) => heading.textContent)).toEqual([
      "Kritik bulgu",
      "Yüksek bulgu",
      "Orta bulgu",
      "Düşük bulgu",
    ]);
  });

  it("teknik ayrıntıları kullanıcı isteğiyle açıp kapatır", async () => {
    const user = userEvent.setup();
    const scan = createScanResult({ findings: [createFinding("high", "Başlık bulgusu")] });
    render(<ScanReportCard scan={scan} onToast={vi.fn()} />);
    const finding = screen.getByRole("heading", { name: "Başlık bulgusu" }).closest("article");

    expect(finding).not.toBeNull();
    const details = within(finding!).getByText("Teknik ayrıntılar").closest("details");
    expect(details).not.toHaveAttribute("open");

    await user.click(within(finding!).getByText("Teknik ayrıntılar"));
    expect(details).toHaveAttribute("open");

    await user.click(within(finding!).getByText("Teknik ayrıntılar"));
    expect(details).not.toHaveAttribute("open");
  });
});
