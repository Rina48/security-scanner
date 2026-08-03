# Security Scanner Repository Rehberi

## Kapsam

- Bu dosya repository'nin tamamı için geçerlidir.
- Kullanıcı görevini ve ileride eklenirse değiştirilen dosyaya en yakın `AGENTS.md` kurallarını izle.
- Düzenlemeden önce ilgili kodu, testleri, yapılandırmayı ve paket scriptlerini incele.

## Projenin Amacı

- Security Scanner, yerel ve açıkça yetkilendirilmiş hedefler için savunma amaçlı bir güvenlik inceleme aracıdır.
- Pasif taramalar HTTP(S) yanıtlarını, başlıkları, cookie'leri, TLS'i ve yanıt sızıntılarını inceler.
- Çevrimdışı body taramaları, canlı hedefe bağlanmadan verilen yanıt metnini analiz eder.
- Aktif taramalar yalnız backend'in sunucu tarafı allowlist'leri exact host'u yetkilendirdiğinde sınırlı probe'lar gönderir.
- Bulgular incelemeyi destekler; hedefin güvenli olduğunu kanıtlamaz.

## Repository Yapısı

- `backend/`: Express API, tarama akışı, güvenlik politikaları, raporlama, kalıcılık ve testler.
- `frontend/`: Tarama, geçmiş ve rapor dışa aktarma için React ve Vite arayüzü.
- `mcp-server/`: Backend API'yi çağıran TypeScript MCP sunucusu.
- `agent/`: Pasif URL taramaları ve yerel Markdown raporları için isteğe bağlı Python istemcisi.
- `shared/`: Uygulama paketleri arasında paylaşılan TypeScript tipleri.

## Güvenlik Sınırları

- Gerçek internet, kurum sistemi, LAN cihazı veya yetkisiz hedef üzerinde aktif tarama yapma.
- Frontend alanını, request body'yi, MCP argümanını veya başka istemci girdisini yetki kabul etme.
- Aktif tarama yetkisini backend'de tut ve sunucu tarafı exact-host allowlist'ini zorunlu kıl.
- Auth, SSRF/egress, DNS/IP, redirect doğrulaması veya adres sabitleme kontrollerini gevşetme.
- Metadata adres deny-list'ini, private ağ kısıtlarını, probe kontrollerini veya host normalizasyonunu gevşetme.
- Probe erişimi açıkça etkinleştirilmiş, kimliği doğrulanmış, yalnız loopback'ten ve sunucu allowlist'inden olmalı.
- Yetki, parsing, DNS, ağ sınıflandırması veya politika kontrolü başarısız olduğunda fail-closed davranışı koru.
- Secret, token, cookie, credential, gerçek hedef, özel rapor veya kullanıcı verisini commit etme ya da çıktıda gösterme.
- `reports/`, `samples/` ve `agent/urls.txt` yerel ve Git tarafından ignored kalmalı.
- `backend/test-fixtures/tls/test-key.pem` yalnız sentetik test fixture'ıdır; production credential değildir.
- Açık kullanıcı talebi olmadan `npm audit fix` gibi geniş otomatik düzeltmeler çalıştırma.
- Fixture veya dokümanlara gerçek hedef, kurum adı, domain, özel IP ya da credential ekleme.

## Kod Kalitesi

- Görevi karşılayan en küçük, eksiksiz ve sürdürülebilir değişikliği yap.
- Mevcut kalıpları ve bağımlılıkları kullan; açık ihtiyaç olmadan bağımlılık ekleme.
- Fail-open güvenlik davranışı oluşturma veya başarısız politika kontrolünü sessizce atlama.
- `AbortSignal` aktarımını, timeout'ları, socket ve dispatcher temizliğini, listener kaldırmayı koru.
- API, schema, CLI davranışı, MCP araçları ve mevcut kullanıcı akışlarında gereksiz uyumsuzluk oluşturma.
- Log ve hata yanıtlarında hassas request, token, cookie, hedef ve rapor içeriği gösterme.
- Güvenlik veya dış davranış değiştiğinde odaklı test ekle ya da mevcut testi güncelle.
- Görev gerektirmedikçe generated output, kurulu bağımlılık veya lockfile değiştirme.

## Zorunlu Doğrulamalar

- Kontrolleri etkilenen paket dizininde ve repository'nin mevcut scriptleriyle çalıştır.
- Odaklı kontrollerle başla, ardından aşağıdaki uygulanabilir paket kontrollerinin tamamını çalıştır.
- Atlanan, kullanılamayan, timeout olan veya başarısız kontrolü başarılı raporlama.
- Backend test keşfinin sıfır test bulması başarı değil, hatadır.

### Backend

Backend kodu, yapılandırması veya testleri etkilendiğinde `backend/` dizininde çalıştır:

```powershell
npm.cmd run typecheck
npm.cmd test
npm.cmd run build
```

### Frontend

Frontend kodu veya yapılandırması etkilendiğinde `frontend/` dizininde çalıştır:

```powershell
npm.cmd run lint
npm.cmd run build
```

### MCP Sunucusu

MCP kodu veya yapılandırması etkilendiğinde `mcp-server/` dizininde çalıştır:

```powershell
npm.cmd run build -- --noEmit
npm.cmd run build
```

### Python Agent

`agent.py` etkilendiğinde `agent/` dizininde çalıştır:

```powershell
python -c "import ast, pathlib; ast.parse(pathlib.Path('agent.py').read_text(encoding='utf-8'))"
```

### Git

Her değişiklikte teslimden önce çalıştır:

```powershell
git diff --check
git status --short --branch
```

## Git Kuralları

- Görev başında düzenlemeden önce aktif branch'i ve çalışma ağacını kontrol et.
- Kullanıcının mevcut değişikliklerini koru; ilgisiz işi silme, üzerine yazma, stage veya commit etme.
- Kullanıcı farklı bir branch istemedikçe mevcut branch'te çalış.
- Açık onay olmadan force-push, amend, rebase, branch veya veri silme ve history rewrite yapma.
- Yalnız görevle ilgili dosyaları stage et ve commit öncesi staged diff'i incele.
- Değişikliğin amacını anlatan açık bir commit mesajı yaz.
- Yalnız kullanıcı istediğinde commit veya push yap ve istenen teslim sırasını izle.
- Push tamamlamak için başarısız doğrulamayı, branch protection'ı, credential veya remote hatasını atlama.

## Raporlama

- Değiştirilen her dosyayı listele.
- Gerçekte çalıştırılan komutları ve gerçek sonuçlarını yaz.
- Atlanan veya kullanılamayan kontrolleri ve neden çalıştırılmadıklarını belirt.
- Kalan riskleri, varsayımları, hataları, engelleri ve doğrulanamayan alanları açıkla.
- Doğrulanmış bulguları genel veya varsayımsal tavsiyelerden ayır.
- Gerçekleşmeyen doğrulama, Git, deployment veya harici işlemi tamamlanmış gibi sunma.
