#!/usr/bin/env python3
"""
Security Scanner AI Agent
=========================
Anthropic Claude tabanlı otonom güvenlik analiz ajanı.
URL listesini okur, pasif tarama yapar, bulguları analiz eder,
Türkçe Markdown raporu reports/ klasörüne kaydeder.

Kullanım:
    python agent.py                             # urls.txt'i kullanır
    python agent.py --url https://example.com   # tek URL
    python agent.py --file hedefler.txt         # özel dosya
    python agent.py --url https://a.com https://b.com  # çoklu URL

Gereksinim:
    ANTHROPIC_API_KEY environment variable set edilmiş olmalı.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any

import anthropic
import requests

# ─── Yapılandırma ─────────────────────────────────────────────────────────────

BACKEND_URL = "http://127.0.0.1:4310"
BACKEND_DIR = Path(__file__).parent.parent / "backend"
AGENT_DIR = Path(__file__).parent
REPORTS_DIR = AGENT_DIR / "reports"
DEFAULT_URLS_FILE = AGENT_DIR / "urls.txt"
MODEL = "claude-3-5-sonnet-latest"
MAX_TOKENS = 8096
MAX_ITERATIONS = 30  # sonsuz döngü koruması

REPORTS_DIR.mkdir(exist_ok=True)

# ─── Backend Yönetimi ──────────────────────────────────────────────────────────

_backend_proc: subprocess.Popen | None = None


def is_backend_running() -> bool:
    try:
        r = requests.get(f"{BACKEND_URL}/api/health", timeout=2)
        return r.ok
    except Exception:
        return False


def wait_for_backend(max_wait: int = 25) -> bool:
    deadline = time.time() + max_wait
    while time.time() < deadline:
        if is_backend_running():
            return True
        time.sleep(0.7)
    return False


def ensure_backend() -> None:
    global _backend_proc
    api_headers()
    if is_backend_running():
        return

    print("[ajan] Backend çalışmıyor, başlatılıyor...", flush=True)

    if not BACKEND_DIR.exists():
        raise RuntimeError(
            f"Backend klasörü bulunamadı: {BACKEND_DIR}\n"
            "security-scanner/backend/ klasörünün mevcut olduğundan emin olun."
        )

    npm_cmd = "npm.cmd" if sys.platform == "win32" else "npm"
    env = os.environ.copy()
    _backend_proc = subprocess.Popen(
        [npm_cmd, "run", "dev"],
        cwd=str(BACKEND_DIR),
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    if not wait_for_backend(25):
        _backend_proc.terminate()
        raise RuntimeError(
            "Backend 25 saniyede başlamadı. "
            "'security-scanner/backend' klasöründe 'npm install' yaptığınızdan emin olun."
        )

    print("[ajan] Backend hazır.\n", flush=True)


def stop_backend() -> None:
    if _backend_proc and _backend_proc.poll() is None:
        _backend_proc.terminate()


# ─── Tarama Araçları ──────────────────────────────────────────────────────────

def api_headers() -> dict[str, str]:
    token = os.environ.get("SECURITY_SCANNER_API_TOKEN", "").strip()
    if len(token) < 32:
        raise RuntimeError("SECURITY_SCANNER_API_TOKEN en az 32 karakter olmalıdır.")
    return {"Authorization": f"Bearer {token}"}

def scan_url(url: str, mode: str = "passive") -> dict[str, Any]:
    """URL'yi güvenlik taramasından geçirir."""
    ensure_backend()
    r = requests.post(
        f"{BACKEND_URL}/api/scans",
        headers=api_headers(),
        json={"targetUrl": url, "mode": mode},
        timeout=90,
    )
    r.raise_for_status()
    return r.json()


def list_recent_scans() -> dict[str, Any]:
    """Son 30 taramayı listeler."""
    ensure_backend()
    r = requests.get(f"{BACKEND_URL}/api/scans", headers=api_headers(), timeout=10)
    r.raise_for_status()
    return r.json()


def scan_body(label: str, body: str) -> dict[str, Any]:
    """Yanıt gövdesini çevrimdışı analiz eder."""
    ensure_backend()
    r = requests.post(
        f"{BACKEND_URL}/api/body-scans",
        headers=api_headers(),
        json={"sourceLabel": label, "body": body},
        timeout=30,
    )
    r.raise_for_status()
    return r.json()


# ─── Araç Tanımları (Claude için) ─────────────────────────────────────────────

TOOLS: list[dict[str, Any]] = [
    {
        "name": "scan_url",
        "description": (
            "Bir URL'yi güvenlik açıkları için tarar. "
            "Pasif mod: güvenlik başlıkları, çerez güvenliği, TLS, sızan sırlar vb. "
            "Aktif mod: SQLi, XSS, path traversal, komut enjeksiyonu — yalnızca sunucu allowlist'i ile açık."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Taranacak URL (örn: https://example.edu.tr)"},
                "mode": {
                    "type": "string",
                    "enum": ["passive", "active"],
                    "description": "passive = yanıt analizi, active = yalnızca sunucu allowlist'indeki hedeflerde SQLi/XSS testleri",
                    "default": "passive",
                },
            },
            "required": ["url"],
        },
    },
    {
        "name": "list_recent_scans",
        "description": "Son 30 taramanın özetini listeler (hedef URL, mod, skor, tarih).",
        "input_schema": {"type": "object", "properties": {}},
    },
    {
        "name": "scan_body",
        "description": (
            "Bir HTTP yanıt gövdesini çevrimdışı analiz eder. "
            "Canlı URL erişimi olmadan kopyalanan içerik veya log üzerinde tarama yapar."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "label": {"type": "string", "description": "Kaynak etiketi (örn: 'uygulama hata sayfası')"},
                "body": {"type": "string", "description": "Analiz edilecek HTTP yanıt gövdesi metni"},
            },
            "required": ["label", "body"],
        },
    },
]


def call_tool(name: str, inputs: dict[str, Any]) -> str:
    """Araç çağrısını yürütür, sonucu JSON string olarak döner."""
    try:
        if name == "scan_url":
            result = scan_url(inputs["url"], inputs.get("mode", "passive"))
        elif name == "list_recent_scans":
            result = list_recent_scans()
        elif name == "scan_body":
            result = scan_body(inputs["label"], inputs["body"])
        else:
            return json.dumps({"error": f"Bilinmeyen araç: {name}"})
        return json.dumps(result, ensure_ascii=False, indent=2)
    except Exception as exc:
        return json.dumps({"error": str(exc)}, ensure_ascii=False)


# ─── Sistem Promptu ───────────────────────────────────────────────────────────

SYSTEM_PROMPT = """Sen kıdemli bir siber güvenlik analistisin. Türkçe yazıyorsun.
Görevin: verilen URL listesini güvenlik açıkları için analiz etmek, bulguları yorumlamak ve kapsamlı bir Türkçe güvenlik raporu üretmek.

Çalışma prensiplerin:
1. Varsayılan olarak passive mod kullan. Active modu yalnızca operatör açıkça istediğinde dene; nihai yetkiyi sunucu allowlist'i belirler.
2. Tüm bulgular toplandıktan sonra onları kritik bilgi sızıntıları, yapılandırma hataları ve genel güvenlik eksiklikleri olarak sınıflandır.
3. Sonunda aşağıdaki formatta yapılandırılmış bir Markdown raporu oluştur:

---
# Güvenlik Analiz Raporu — {tarih}

## Özet Tablo
| Site | Kritik | Yüksek | Orta | Düşük | Skor | Risk Seviyesi |
|------|--------|--------|------|-------|------|---------------|
| ... | ... | ... | ... | ... | ... | ... |

## En Kritik Bulgular (Tüm Siteler)
(Tüm sitelerdeki kritik ve yüksek bulgular liste halinde)

## Site Analizleri

### [site adı]
**Risk Seviyesi:** ...  
**Güvenlik Skoru:** .../100  
**Özet:** (2-3 cümle)

#### Kritik Bulgular
- ...

#### Yüksek Bulgular
- ...

#### Öneriler
1. ...

---

## Genel Değerlendirme
(Tüm siteleri kapsayan genel güvenlik değerlendirmesi)

## Öncelikli Eylem Listesi
1. ...
---

ETİK UYARI: Aktif tarama yalnızca sunucu tarafında açıkça allowlist'e alınmış ve yetkilendirilmiş hedeflerde çalışır."""


# ─── ReAct Ajan Döngüsü ───────────────────────────────────────────────────────

def run_agent(urls: list[str]) -> str:
    """
    ReAct döngüsü: Düşün → Araç Çağır → Gözlemle → Tekrarla → Rapor Yaz.
    Sonuçta Türkçe Markdown rapor metni döner.
    """
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        raise RuntimeError(
            "ANTHROPIC_API_KEY environment variable bulunamadı.\n"
            "Lütfen: set ANTHROPIC_API_KEY=sk-ant-..."
        )

    client = anthropic.Anthropic(api_key=api_key)

    url_list = "\n".join(f"- {u}" for u in urls)
    initial_message = (
        f"Aşağıdaki URL'leri güvenlik açıkları için analiz et ve kapsamlı bir Türkçe rapor oluştur:\n\n"
        f"{url_list}\n\n"
        f"Tüm URL'lerde varsayılan olarak passive mod kullan. "
        f"Tüm taramalar tamamlandıktan sonra raporu yaz."
    )

    messages: list[dict[str, Any]] = [{"role": "user", "content": initial_message}]

    print(f"[ajan] {len(urls)} URL için analiz başlıyor...\n", flush=True)

    for iteration in range(MAX_ITERATIONS):
        response = client.messages.create(
            model=MODEL,
            max_tokens=MAX_TOKENS,
            system=SYSTEM_PROMPT,
            tools=TOOLS,  # type: ignore[arg-type]
            messages=messages,  # type: ignore[arg-type]
        )

        # Asistan mesajını geçmişe ekle
        messages.append({"role": "assistant", "content": response.content})  # type: ignore[arg-type]

        if response.stop_reason == "end_turn":
            # Raporu çıkart
            for block in response.content:
                if hasattr(block, "text"):
                    return block.text
            break

        if response.stop_reason != "tool_use":
            break

        # Araç çağrılarını işle
        tool_results: list[dict[str, Any]] = []
        for block in response.content:
            if block.type != "tool_use":
                continue

            tool_name: str = block.name
            tool_input: dict[str, Any] = block.input  # type: ignore[assignment]

            print(f"[ajan] Araç çağrısı: {tool_name}({json.dumps(tool_input, ensure_ascii=False)})", flush=True)

            result_text = call_tool(tool_name, tool_input)
            tool_results.append({
                "type": "tool_result",
                "tool_use_id": block.id,
                "content": result_text,
            })

            # Kısa özet yazdır
            try:
                parsed = json.loads(result_text)
                if "findings" in parsed:
                    count = len(parsed["findings"])
                    score = parsed.get("score", "?")
                    print(f"         → {count} bulgu, skor: {score}/100", flush=True)
            except Exception:
                pass

        messages.append({"role": "user", "content": tool_results})  # type: ignore[arg-type]

    return "[Rapor üretilemedi — ajan döngüsü beklenmeden sona erdi.]"


# ─── Rapor Kaydetme ───────────────────────────────────────────────────────────

def save_report(content: str) -> Path:
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M")
    path = REPORTS_DIR / f"guvenlik-raporu-{timestamp}.md"
    path.write_text(content, encoding="utf-8")
    return path


# ─── CLI ──────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Security Scanner AI Agent — Türkçe güvenlik analiz ajanı"
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--url",
        nargs="+",
        metavar="URL",
        help="Taranacak URL(ler) (örn: https://example.edu.tr)",
    )
    group.add_argument(
        "--file",
        metavar="DOSYA",
        help="URL listesi içeren dosya yolu (varsayılan: urls.txt)",
    )
    return parser.parse_args()


def load_urls(args: argparse.Namespace) -> list[str]:
    if args.url:
        return args.url

    file_path = Path(args.file) if args.file else DEFAULT_URLS_FILE

    if not file_path.exists():
        print(f"[hata] URL dosyası bulunamadı: {file_path}", file=sys.stderr)
        print("       --url veya --file argümanı kullanın, ya da urls.txt oluşturun.", file=sys.stderr)
        sys.exit(1)

    urls = [
        line.strip()
        for line in file_path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]

    if not urls:
        print(f"[hata] {file_path} dosyasında geçerli URL bulunamadı.", file=sys.stderr)
        sys.exit(1)

    return urls


def main() -> None:
    args = parse_args()
    urls = load_urls(args)

    print("=" * 60)
    print("  Security Scanner AI Agent")
    print(f"  Hedef: {len(urls)} URL")
    print(f"  Model: {MODEL}")
    print("=" * 60)
    print()

    try:
        report = run_agent(urls)
        report_path = save_report(report)

        print("\n" + "=" * 60)
        print(f"  Rapor kaydedildi: {report_path}")
        print("=" * 60)
        print("\n" + report)

    except KeyboardInterrupt:
        print("\n[ajan] İptal edildi.", file=sys.stderr)
    finally:
        stop_backend()


if __name__ == "__main__":
    main()
