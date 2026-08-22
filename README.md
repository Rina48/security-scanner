# Security Scanner

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![CI](https://github.com/Rina48/security-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/Rina48/security-scanner/actions/workflows/ci.yml)
![Node.js](https://img.shields.io/badge/Node.js-%3E%3D20-green.svg)
![TypeScript](https://img.shields.io/badge/TypeScript-5.x-3178C6.svg)
![MCP Ready](https://img.shields.io/badge/MCP-Model%20Context%20Protocol-8A2BE2.svg)

Security Scanner, HTTP(S) hedeflerinde pasif yanıt analizi ve açıkça yetkilendirilmiş hedeflerde sınırlı aktif kontroller çalıştıran yerel bir güvenlik inceleme aracıdır. **TypeScript backend**, **React web arayüzü**, LLM/IDE entegrasyonu için **Model Context Protocol (MCP) sunucusu** ve otonom raporlama için isteğe bağlı **Python AI agent** bileşenlerinden oluşur.

---

> [!WARNING]
> **YASAL VE ETİK UYARI (DISCLAIMER)**<br>
> Bu araç savunma amaçlı güvenlik analizleri, yerel geliştirme denetimleri ve açıkça izin verilmiş hedefler için geliştirilmiştir. Yetkisiz sistemler, LAN cihazları veya üçüncü taraf altyapılar üzerinde izinsiz tarama yapılması yasaktır ve yasal sorumluluk doğurur. Bulgular güvenlik incelemesini destekler; bir sistemin mutlak güvenli olduğunu kanıtlamaz.

---

## Öne Çıkan Özellikler

- **Pasif Güvenlik Analizi**: HTTP yanıt başlıkları (HSTS, CSP, X-Frame-Options vb.), cookie güvenlik bayrakları (`HttpOnly`, `Secure`, `SameSite`) ve hassas bilgi sızıntılarını (API anahtarları, JWT, hata izleri) inceler.
- **TLS ve Sertifika Denetimi**: Sertifika geçerlilik süreleri, hostname eşleşmesi ve güven zincirini doğrular.
- **Çevrimdışı Gövde (Body) Analizi**: Canlı hedefe istek atmadan, kopyalanan HTTP yanıt metnini veya hata loglarını analiz eder.
- **Sunucu Tarafı Güvenli Aktif Tarama**: Yalnız backend `ALLOWED_ACTIVE_HOSTS` exact allowlist'inde yer alan hedeflerde sınırlı SQLi/XSS/Traversal kontrolleri yürütür.
- **Model Context Protocol (MCP) Desteği**: Claude Desktop, Cursor, Claude Code ve diğer AI araçlarıyla doğrudan stdio üzerinden konuşarak yapay zekanın otonom güvenlik denetimleri yapmasını sağlar.
- **Kaynak ve SSRF Koruması**: Fail-closed mimari, metadata IP koruması, pinned DNS çözümü ve global hız/kaynak limitleri.

---

## Güvenlik Modeli

- Backend varsayılan olarak yalnız IPv4 loopback (`127.0.0.1:4310`) üzerinde dinler. Dış ağ arayüzlerine açılmamalıdır.
- `/api/health` dışındaki tüm rotalar Bearer token doğrulaması ister. `SECURITY_SCANNER_API_TOKEN` en az 32 karakter olmalıdır.
- Tarayıcı Origin adresleri `SECURITY_SCANNER_ALLOWED_ORIGINS` ile sınırlandırılmıştır.
- Pasif istekler SSRF, DNS sabitleme, link-local ve metadata IP filtrelerinden geçer.
- Aktif tarama izni istemci/frontend girdisine göre değil, backend sunucusundaki `ALLOWED_ACTIVE_HOSTS` listesine göre belirlenir.

### Kaynak Limitleri

| Ortam Değişkeni | Varsayılan | Açıklama |
| --- | ---: | --- |
| `SECURITY_SCANNER_MAX_CONCURRENT_SCANS` | `2` | Aynı anda çalışan global tarama sayısı |
| `SECURITY_SCANNER_MAX_QUEUED_SCANS` | `8` | Scheduler kuyruk derinliği |
| `SECURITY_SCANNER_MAX_ASYNC_JOBS` | `8` | Bellekte izlenen asenkron iş sayısı |
| `SECURITY_SCANNER_RATE_LIMIT_MAX` | `20` | Hız penceresindeki azami tarama başlatma |
| `SECURITY_SCANNER_RATE_LIMIT_WINDOW_MS` | `60000` | Tarama başlangıç hız penceresi (ms) |
| `SECURITY_SCANNER_MAX_RESPONSE_BODY_BYTES` | `1048576` | Tek yanıtta okunan azami byte (1 MB) |
| `SECURITY_SCANNER_MAX_REQUESTS_PER_SCAN` | `128` | Tarama başına hedefe giden azami istek sayısı |
| `SECURITY_SCANNER_ASYNC_JOB_TTL_MS` | `600000` | Asenkron iş zaman aşımı (ms) |

---

## Mimari

- `backend/`: Express API, tarayıcı modülleri, egress politikaları, raporlama ve SQLite geçmişi.
- `frontend/`: React 19 ve Vite tabanlı yerel kullanıcı arayüzü; URL/Body analizi, geçmiş ve Markdown/JSON dışa aktarma.
- `mcp-server/`: Model Context Protocol (MCP) standardında stdio sunucusu (Cursor, Claude Desktop, Claude Code desteği).
- `agent/`: Claude ile otonom URL listesi tarayan ve kapsamlı Türkçe Markdown raporu üreten Python ajanı.
- `shared/`: Frontend ve Backend arasında paylaşılan TypeScript tipleri.

---

## Hızlı Başlangıç

### 1. Yapılandırma
Örnek ortam dosyasını referans alarak yapılandırmanızı hazırlayın:
```powershell
Copy-Item .env.example .env
```

### 2. Backend Başlatma
```powershell
cd backend
npm ci
$env:SECURITY_SCANNER_API_TOKEN = "en-az-32-karakterlik-guvenli-rastgele-token"
$env:SECURITY_SCANNER_ALLOWED_ORIGINS = "http://127.0.0.1:5173"
npm run dev
```

### 3. Frontend Web Arayüzü
```powershell
cd frontend
npm ci
npm run dev -- --host 127.0.0.1
```
Tarayıcınızda `http://127.0.0.1:5173` adresine gidin ve API tokenınızı girerek taramaları başlatın.

---

## MCP Sunucusu (Claude Desktop & Cursor Entegrasyonu)

Security Scanner, LLM tabanlı geliştirme araçlarının doğrudan güvenlik taraması yapabilmesi için yerleşik bir **MCP (Model Context Protocol)** sunucusu içerir.

### Sunulan MCP Araçları
- `scan_url`: URL pasif veya (izinliyse) aktif güvenlik taraması yapar.
- `scan_body`: Canlı bağlantı olmadan kopyalanan HTTP gövdesini çevrimdışı analiz eder.
- `list_recent_scans`: Son 30 tarama kaydını ve skorlarını listeler.
- `get_scan`: Belirli bir taramanın ayrıntılı bulgu dökümünü getirir.
- `clear_scans`: Tarama geçmişini temizler.

### Claude Desktop / Cursor Konfigürasyonu
`claude_desktop_config.json` dosyanıza veya Cursor MCP ayarlarına aşağıdaki bloğu ekleyin:

```json
{
  "mcpServers": {
    "security-scanner": {
      "command": "node",
      "args": ["<PROJE_YOLU>/mcp-server/dist/index.js"],
      "env": {
        "SECURITY_SCANNER_API_TOKEN": "en-az-32-karakterlik-guvenli-rastgele-token",
        "SECURITY_SCANNER_BACKEND_URL": "http://127.0.0.1:4310"
      }
    }
  }
}
```

> **Not**: Kullanmadan önce `cd mcp-server && npm ci && npm run build` çalıştırıldığından emin olun.

---

## Python AI Agent (Otonom Analiz)

İsteğe bağlı Python ajanı, bir URL listesini toplu tarayarak Claude ile analiz eder ve yapılandırılmış raporlar üretir:

```powershell
cd agent
Copy-Item urls.example.txt urls.txt
# urls.txt dosyasını yetkili hedeflerinizle düzenleyin
python -m pip install --require-hashes -r requirements.txt
$env:ANTHROPIC_API_KEY = "sk-ant-..."
$env:SECURITY_SCANNER_API_TOKEN = "en-az-32-karakterlik-guvenli-rastgele-token"
python agent.py
```

---

## Doğrulama ve Testler

Her paketin test ve derleme kontrollerini ilgili dizinde çalıştırabilirsiniz:

```powershell
# Backend (115+ test & typecheck)
cd backend && npm run typecheck && npm test && npm run build

# Frontend (Vitest & ESLint)
cd frontend && npm run lint && npm test && npm run build

# MCP Sunucusu
cd mcp-server && npm run build -- --noEmit && npm run build

# Python Agent
cd agent && python -c "import ast, pathlib; ast.parse(pathlib.Path('agent.py').read_text(encoding='utf-8'))"
```

---

## Repository Yapısı

```text
.
├── backend/          # Express API, tarayıcı motorları, güvenlik politikaları ve testler
├── frontend/         # React 19 + Vite kullanıcı arayüzü
├── mcp-server/       # Stdio tabanlı Model Context Protocol (MCP) sunucusu
├── agent/            # Otonom Python analiz ajanı ve örnek hedef listesi
├── shared/           # Ortak TypeScript tip tanımları
├── .env.example      # Örnek ortam değişkenleri şablonu
├── .gitignore        # Sertleştirilmiş Git hariç tutma kuralları
├── LICENSE           # GNU Affero General Public License v3.0 (AGPL-3.0)
└── README.md
```

---

## Lisans

Bu proje **GNU Affero General Public License v3.0 (AGPL-3.0)** altında lisanslanmıştır. Ayrıntılar için [LICENSE](LICENSE) dosyasına bakabilirsiniz.
