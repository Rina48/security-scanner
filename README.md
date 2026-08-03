# Security Scanner

Security Scanner, HTTP(S) hedeflerinde pasif yanıt analizi ve açıkça yetkilendirilmiş hedeflerde sınırlı aktif kontroller çalıştıran yerel bir güvenlik inceleme aracıdır. TypeScript backend, React arayüzü, MCP sunucusu ve isteğe bağlı Python agent bileşenlerinden oluşur. Bulgular inceleme desteği sağlar; tek başına güvenlik garantisi vermez.

## Ne yapar?

- HTTP yanıtlarını güvenlik başlıkları, cookie ayarları ve bilgi sızıntıları açısından inceler.
- TLS sertifikası ve protokol desteğiyle ilgili doğrulanabilir bulgular üretir.
- Kopyalanmış bir HTTP yanıt gövdesini canlı hedefe bağlanmadan analiz eder.
- Yalnız sunucu tarafında izin verilen hedeflerde sınırlı aktif kontroller çalıştırır.
- Bulguları önem, güven ve risk skoruyla raporlar; son taramaları yerel SQLite veritabanında tutar.
- Tarama, geçmiş görüntüleme ve rapor dışa aktarma için bir web arayüzü sağlar.
- Aynı backend işlevlerini MCP araçları ve isteğe bağlı Python agent üzerinden kullanabilir.

## Güvenlik modeli

- Backend varsayılan olarak yalnız `127.0.0.1:4310` üzerinde dinler. Ağ arayüzlerine açmadan yerel kullanın.
- `/api/health` dışındaki API rotaları Bearer token ister. `SECURITY_SCANNER_API_TOKEN` en az 32 karakter olmalıdır.
- Tarayıcı erişimi için izin verilen origin'ler `SECURITY_SCANNER_ALLOWED_ORIGINS` ile açıkça tanımlanır.
- Pasif istekler HTTP(S), DNS, yönlendirme ve ağ adresi politikalarından geçer; metadata ve riskli yerel ağ adresleri varsayılan olarak reddedilir.
- Aktif tarama, hedef hostname'i `ALLOWED_ACTIVE_HOSTS` exact-host allowlist'inde yoksa reddedilir. Private hedefler ayrıca `ALLOWED_ACTIVE_PRIVATE_HOSTS` içinde olmalıdır.
- Tarama başlangıçları global eşzamanlılık, kuyruk, asenkron iş, hız, hedef istek ve uzak yanıt boyutu limitlerinden geçer. Kapasite kontrolleri backend'de uygulanır.
- Gerçek hedefleri yalnız açık ve güncel yetkiniz varsa tarayın. Üçüncü taraf sistemlerde izinsiz kullanım yapmayın.
- Python agent isteğe bağlıdır ve kullanıldığında Anthropic API ile iletişim kurar; backend, frontend ve MCP yerel servisler olarak çalışabilir.

### Kaynak limitleri

Limitler environment değişkenleriyle değiştirilebilir. Geçersiz değerler sunucu başlangıcını fail-closed durdurur.

| Environment değişkeni | Varsayılan | Açıklama |
| --- | ---: | --- |
| `SECURITY_SCANNER_MAX_CONCURRENT_SCANS` | `2` | Aynı anda çalışan global tarama sayısı |
| `SECURITY_SCANNER_MAX_QUEUED_SCANS` | `8` | Scheduler'da bekleyebilen tarama sayısı |
| `SECURITY_SCANNER_MAX_ASYNC_JOBS` | `8` | Bellekte izlenen asenkron iş sayısı |
| `SECURITY_SCANNER_RATE_LIMIT_MAX` | `20` | Hız penceresinde kabul edilen tarama başlangıcı |
| `SECURITY_SCANNER_RATE_LIMIT_WINDOW_MS` | `60000` | Tarama başlangıç hız penceresi (ms) |
| `SECURITY_SCANNER_MAX_RESPONSE_BODY_BYTES` | `1048576` | Tek uzak HTTP yanıtında okunan en fazla byte |
| `SECURITY_SCANNER_MAX_REQUESTS_PER_SCAN` | `128` | Tek taramada hedefe gönderilebilen HTTP/TLS ağ isteği |
| `SECURITY_SCANNER_ASYNC_JOB_TTL_MS` | `600000` | Asenkron iş kaydı ve çalışma süresi üst sınırı (ms) |

Kapasite dolduğunda API `503`, hız sınırı aşıldığında `429` ve `Retry-After` döndürür. Uzak yanıt veya hedef istek bütçesi aşıldığında ilgili okuma/tarama durdurulur.

## Mimari

- `backend/`: Express tabanlı API, tarama akışı, egress politikaları, raporlama ve yerel SQLite geçmişi.
- `frontend/`: Vite ve React tabanlı yerel arayüz; URL/gövde analizi, geçmiş ve rapor dışa aktarma.
- `mcp-server/`: Backend API'yi stdio üzerinden MCP araçları olarak sunan TypeScript sunucusu.
- `agent/`: URL listesini pasif tarayan ve Türkçe Markdown raporu oluşturan isteğe bağlı Python agent.
- `shared/`: Frontend ve backend arasında kullanılan ortak TypeScript tipleri.

## Gereksinimler

- Node.js ve npm
- Lock dosyalarıyla kurulum için `npm ci`
- Python agent kullanılacaksa Python 3.10 veya üzeri
- Agent için `anthropic` ve `requests` paketleri
- Agent kullanılacaksa `ANTHROPIC_API_KEY`
- Backend, MCP ve agent için aynı `SECURITY_SCANNER_API_TOKEN`
- Yalnız yetkili test hedefleri

## Hızlı başlangıç

Aşağıdaki komut bloklarını repository kökünden, ayrı PowerShell oturumlarında çalıştırın.

### Backend

```powershell
cd backend
npm ci
$env:SECURITY_SCANNER_API_TOKEN = Read-Host "En az 32 karakterlik yerel token"
$env:SECURITY_SCANNER_ALLOWED_ORIGINS = "http://127.0.0.1:5173"
npm run dev
```

Sağlık kontrolü `http://127.0.0.1:4310/api/health` adresindedir. Diğer `/api` rotalarında aynı token Bearer kimlik bilgisi olarak kullanılmalıdır.

### Frontend

```powershell
cd frontend
npm ci
npm run dev -- --host 127.0.0.1
```

Vite'ın gösterdiği yerel adresi açın ve backend için tanımladığınız tokenı arayüze girin. Frontend varsayılan olarak `http://127.0.0.1:4310` backend adresini kullanır; gerekirse `VITE_API_BASE_URL` ile değiştirilebilir.

### Yerel hedef listesi ve Python agent

Örnek dosyayı yerel hedef listesine kopyalayın, ardından yalnız tarama yetkiniz olan adreslerle düzenleyin:

```powershell
Copy-Item agent\urls.example.txt agent\urls.txt
```

`agent/urls.txt` Git tarafından ignore edilir. Agent kullanacaksanız `ANTHROPIC_API_KEY` ve backend ile aynı `SECURITY_SCANNER_API_TOKEN` ortam değişkenlerini tanımlayın:

```powershell
cd agent
python -m pip install --require-hashes -r requirements.txt
python agent.py
```

`agent/requirements.in` doğrudan bağımlılıkları kesin sürümlerle tanımlar; `requirements.txt` ise temiz ve tekrarlanabilir kurulum için transitif bağımlılıkları SHA-256 hash'leriyle kilitler.

Aktif moda geçmeden önce hedef hostname'lerini backend process ortamında `ALLOWED_ACTIVE_HOSTS` ile açıkça izinli hale getirin. Allowlist boşken aktif tarama reddedilir.

## Doğrulama

Her komut grubunu ilgili klasörde çalıştırın.

### Backend

```powershell
cd backend
npm ci
npm run typecheck
npm test
npm run build
```

### Frontend

```powershell
cd frontend
npm ci
npm run lint
npm run build
```

### MCP

```powershell
cd mcp-server
npm ci
.\node_modules\.bin\tsc.CMD -p tsconfig.json --noEmit
npm run build
```

### Python

```powershell
cd agent
python -c "import ast, pathlib; ast.parse(pathlib.Path('agent.py').read_text(encoding='utf-8'))"
```

## Sınırlamalar

- Araç, bir sistemin güvenli olduğunu kanıtlamaz ve tüm güvenlik açıklarını bulma garantisi vermez.
- Bulgular bağlam ve yanlış pozitif olasılığı açısından yetkin bir kişi tarafından incelenmelidir.
- Yalnız sahibi olduğunuz veya test izni aldığınız hedeflerde kullanılmalıdır.
- Aktif tarama varsayılan olarak yetkisizdir; sunucu tarafı allowlist olmadan çalışmaz.
- Ağ politikaları ve zaman aşımları bazı kontrolleri sonuçsuz bırakabilir.

## Repository yapısı

```text
.
├── backend/       # API, tarayıcılar, güvenlik politikaları ve testler
├── frontend/      # React kullanıcı arayüzü
├── mcp-server/    # MCP stdio sunucusu
├── agent/         # İsteğe bağlı Python agent ve örnek URL listesi
├── shared/        # Ortak TypeScript tipleri
├── .gitignore
└── README.md
```
