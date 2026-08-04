import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  analyzeBody,
  ApiClientError,
  clearScans,
  connectToApi,
  createScan,
  fetchScans,
} from "../apiClient";
import { createScanResult } from "../test/fixtures";
import type { ScanResult } from "../types";
import { ScannerPage } from "./ScannerPage";

vi.mock("../apiClient", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../apiClient")>();
  return {
    ...actual,
    analyzeBody: vi.fn(),
    clearScans: vi.fn(),
    connectToApi: vi.fn(),
    createScan: vi.fn(),
    fetchScans: vi.fn(),
  };
});

const analyzeBodyMock = vi.mocked(analyzeBody);
const clearScansMock = vi.mocked(clearScans);
const connectToApiMock = vi.mocked(connectToApi);
const createScanMock = vi.mocked(createScan);
const fetchScansMock = vi.mocked(fetchScans);

async function connect(user: ReturnType<typeof userEvent.setup>, token = "session-token") {
  await user.type(screen.getByRole("textbox", { name: /^API token/ }), token);
  await user.click(screen.getByRole("button", { name: "Bağlan" }));
  await screen.findByText("API hazır. Tarama ve geçmiş işlemlerini kullanabilirsiniz.");
}

describe("ScannerPage", () => {
  beforeEach(() => {
    analyzeBodyMock.mockReset();
    clearScansMock.mockReset();
    connectToApiMock.mockReset();
    createScanMock.mockReset();
    fetchScansMock.mockReset();
    localStorage.clear();
    connectToApiMock.mockResolvedValue([]);
    createScanMock.mockResolvedValue(createScanResult());
    analyzeBodyMock.mockResolvedValue(createScanResult());
    clearScansMock.mockResolvedValue();
    fetchScansMock.mockResolvedValue([]);
  });

  it("token yazarken otomatik geçmiş isteği yapmaz", async () => {
    const user = userEvent.setup();
    render(<ScannerPage />);

    await user.type(screen.getByRole("textbox", { name: /^API token/ }), "henüz-bağlanmadı");

    expect(connectToApiMock).not.toHaveBeenCalled();
    expect(fetchScansMock).not.toHaveBeenCalled();
    expect(screen.getByText("Geçmiş henüz yüklenmedi")).toBeInTheDocument();
  });

  it("geçerli token ile bağlanır ve geçmişi gösterir", async () => {
    const user = userEvent.setup();
    const historyScan = createScanResult({ targetUrl: "https://history.example.test" });
    connectToApiMock.mockResolvedValue([historyScan]);
    render(<ScannerPage />);

    await connect(user, "geçerli-token");

    expect(connectToApiMock).toHaveBeenCalledWith("geçerli-token");
    expect(screen.getByText("Bağlı")).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "https://history.example.test raporunu aç" }),
    ).toBeInTheDocument();
  });

  it("geçersiz tokenı başarılı bağlantıdan ayırır", async () => {
    const user = userEvent.setup();
    connectToApiMock.mockRejectedValue(
      new ApiClientError("invalid-token", "API token kabul edilmedi.", 401),
    );
    render(<ScannerPage />);

    await user.type(screen.getByRole("textbox", { name: /^API token/ }), "geçersiz-token");
    await user.click(screen.getByRole("button", { name: "Bağlan" }));

    expect(await screen.findByText("Token geçersiz")).toBeInTheDocument();
    expect(screen.getByRole("alert")).toHaveTextContent(
      "Token kabul edilmedi. Tokenı kontrol edip yeniden deneyin.",
    );
    expect(screen.queryByText("Bağlı")).not.toBeInTheDocument();
  });

  it("tokenı kalıcı tarayıcı depolamasına yazmaz", async () => {
    const storageSpy = vi.spyOn(Storage.prototype, "setItem");
    const user = userEvent.setup();
    const token = "yalnızca-bellekte-kalan-token";
    render(<ScannerPage />);

    await connect(user, token);

    const persistedValues = storageSpy.mock.calls.map(([, value]) => value).join(" ");
    expect(persistedValues).not.toContain(token);
  });

  it("tarama sürerken çift gönderimi engeller", async () => {
    const user = userEvent.setup();
    let resolveScan!: (scan: ScanResult) => void;
    createScanMock.mockReturnValue(
      new Promise<ScanResult>((resolve) => {
        resolveScan = resolve;
      }),
    );
    render(<ScannerPage />);
    await connect(user);
    await user.type(screen.getByRole("textbox", { name: "Hedef URL" }), "https://scan.example.test");

    await user.dblClick(screen.getByRole("button", { name: "Taramayı başlat" }));

    expect(createScanMock).toHaveBeenCalledTimes(1);
    expect(screen.getByRole("button", { name: "Tarama sürüyor…" })).toBeDisabled();

    resolveScan(createScanResult({ targetUrl: "https://scan.example.test" }));
    expect(await screen.findByText("Tarama tamamlandı")).toBeInTheDocument();
  });

  it("iptal edilen taramayı sonuç veya hata yerine iptal durumunda gösterir", async () => {
    const user = userEvent.setup();
    createScanMock.mockImplementation(
      (_token, _targetUrl, _mode, options) =>
        new Promise<ScanResult>((_resolve, reject) => {
          options?.signal?.addEventListener(
            "abort",
            () => reject(new DOMException("Aborted", "AbortError")),
            { once: true },
          );
        }),
    );
    render(<ScannerPage />);
    await connect(user);
    await user.type(screen.getByRole("textbox", { name: "Hedef URL" }), "https://scan.example.test");
    await user.click(screen.getByRole("button", { name: "Taramayı başlat" }));

    await user.click(screen.getByRole("button", { name: "Taramayı iptal et" }));

    const cancelledTitle = await screen.findByText("Tarama iptal edildi");
    expect(cancelledTitle).toBeInTheDocument();
    expect(cancelledTitle.closest('[role="status"]')).toHaveTextContent(
      "İptal edilen URL taraması sonuç veya hata olarak gösterilmedi.",
    );
    expect(screen.queryByRole("heading", { name: "Genel risk durumu" })).not.toBeInTheDocument();
  });

  it("yetkisiz aktif tarama hatasını anlaşılır eylemle gösterir", async () => {
    const user = userEvent.setup();
    createScanMock.mockRejectedValue(
      new ApiClientError(
        "target-not-authorized",
        "Bu hedef seçilen tarama için yetkili değil.",
        403,
      ),
    );
    render(<ScannerPage />);
    await connect(user);
    await user.type(screen.getByRole("textbox", { name: "Hedef URL" }), "https://lab.example.test");
    await user.click(screen.getByRole("radio", { name: /Aktif tarama/ }));
    await user.click(screen.getByRole("button", { name: "Taramayı başlat" }));

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("Aktif tarama yetkili değil");
    expect(alert).toHaveTextContent("Bu hedef sunucunun aktif tarama izin listesinde değil.");
    expect(alert).toHaveTextContent("İzinli bir local/lab hedefi seçin veya pasif tarama kullanın.");
  });
});
