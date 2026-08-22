# Security Scanner

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![CI](https://github.com/Rina48/security-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/Rina48/security-scanner/actions/workflows/ci.yml)
![Node.js](https://img.shields.io/badge/Node.js-%3E%3D20-green.svg)
![TypeScript](https://img.shields.io/badge/TypeScript-5.x-3178C6.svg)
![MCP Ready](https://img.shields.io/badge/MCP-Model%20Context%20Protocol-8A2BE2.svg)

A local security review tool that runs passive response analysis against HTTP(S) targets and a limited set of active checks against explicitly authorized ones. It ships as four parts: a **TypeScript backend**, a **React web UI**, a **Model Context Protocol (MCP) server** for LLM and IDE integration, and an optional **Python AI agent** for autonomous reporting.

Türkçe sürüm: [README.tr.md](README.tr.md)

---

> [!WARNING]
> **Legal and ethical notice**<br>
> This tool is built for defensive security analysis, local development audits, and targets you are explicitly permitted to test. Scanning systems you do not own or have written authorization for, including LAN devices and third-party infrastructure, is prohibited and may carry legal consequences. Findings support a security review; they do not prove a system is safe.

---

## Features

- **Passive analysis.** Inspects HTTP response headers (HSTS, CSP, X-Frame-Options and others), cookie flags (`HttpOnly`, `Secure`, `SameSite`), and leaked secrets in response bodies (API keys, JWTs, stack traces).
- **TLS and certificate checks.** Validates expiry windows, hostname match, and the trust chain.
- **Offline body analysis.** Analyzes a pasted HTTP response or error log without sending a single request to a live host.
- **Server-side gated active scanning.** Runs a limited set of SQLi, XSS, and traversal checks only against hosts listed in the backend's exact `ALLOWED_ACTIVE_HOSTS` allowlist.
- **Model Context Protocol support.** Talks to Claude Desktop, Cursor, Claude Code and other AI tools over stdio, so an assistant can run security reviews on its own.
- **SSRF and resource protection.** Fail-closed egress policy, metadata IP blocking, pinned DNS resolution, and global rate and resource caps.

---

## Security model

- The backend binds to IPv4 loopback only (`127.0.0.1:4310`) by default and is not meant to be exposed on an external interface.
- Every route except `/api/health` requires Bearer token authentication. `SECURITY_SCANNER_API_TOKEN` must be at least 32 characters.
- Browser origins are restricted through `SECURITY_SCANNER_ALLOWED_ORIGINS`.
- Passive requests pass through SSRF, DNS pinning, link-local, and metadata IP filters.
- Active scanning permission comes from the backend's `ALLOWED_ACTIVE_HOSTS` list, never from client or frontend input.

### Resource limits

| Environment variable | Default | Description |
| --- | ---: | --- |
| `SECURITY_SCANNER_MAX_CONCURRENT_SCANS` | `2` | Global number of scans running at once |
| `SECURITY_SCANNER_MAX_QUEUED_SCANS` | `8` | Scheduler queue depth |
| `SECURITY_SCANNER_MAX_ASYNC_JOBS` | `8` | Async jobs tracked in memory |
| `SECURITY_SCANNER_RATE_LIMIT_MAX` | `20` | Scan starts allowed per rate window |
| `SECURITY_SCANNER_RATE_LIMIT_WINDOW_MS` | `60000` | Scan start rate window (ms) |
| `SECURITY_SCANNER_MAX_RESPONSE_BODY_BYTES` | `1048576` | Max bytes read from a single response (1 MB) |
| `SECURITY_SCANNER_MAX_REQUESTS_PER_SCAN` | `128` | Max requests sent to a target per scan |
| `SECURITY_SCANNER_ASYNC_JOB_TTL_MS` | `600000` | Async job timeout (ms) |

---

## Architecture

- `backend/` — Express API, scanner modules, egress policy, reporting, and SQLite scan history.
- `frontend/` — Local UI built on React 19 and Vite: URL and body analysis, history, Markdown and JSON export.
- `mcp-server/` — Stdio server implementing the Model Context Protocol (Cursor, Claude Desktop, Claude Code).
- `agent/` — Python agent that scans a list of URLs autonomously with Claude and writes a structured Markdown report (report output is in Turkish).
- `shared/` — TypeScript types shared between frontend and backend.

---

## Quick start

Commands below use a POSIX shell. On Windows PowerShell, replace `cp` with `Copy-Item` and `export VAR=value` with `$env:VAR = "value"`.

### 1. Configuration

```bash
cp .env.example .env
```

### 2. Backend

```bash
cd backend
npm ci
export SECURITY_SCANNER_API_TOKEN="a-secure-random-token-of-at-least-32-characters"
export SECURITY_SCANNER_ALLOWED_ORIGINS="http://127.0.0.1:5173"
npm run dev
```

### 3. Frontend

```bash
cd frontend
npm ci
npm run dev -- --host 127.0.0.1
```

Open `http://127.0.0.1:5173`, enter your API token, and start scanning.

---

## MCP server (Claude Desktop and Cursor)

The project includes a built-in **Model Context Protocol** server so LLM-based development tools can run security scans directly.

### Tools exposed

- `scan_url` — Runs a passive scan of a URL, or an active one if the host is allowlisted.
- `scan_body` — Analyzes a pasted HTTP body offline, with no network connection.
- `list_recent_scans` — Lists the last 30 scans and their scores.
- `get_scan` — Returns the full finding breakdown for one scan.
- `clear_scans` — Clears scan history.

### Configuration

Add this block to `claude_desktop_config.json` or your Cursor MCP settings:

```json
{
  "mcpServers": {
    "security-scanner": {
      "command": "node",
      "args": ["<PROJECT_PATH>/mcp-server/dist/index.js"],
      "env": {
        "SECURITY_SCANNER_API_TOKEN": "a-secure-random-token-of-at-least-32-characters",
        "SECURITY_SCANNER_BACKEND_URL": "http://127.0.0.1:4310"
      }
    }
  }
}
```

> **Note:** run `cd mcp-server && npm ci && npm run build` before first use.

---

## Python AI agent

The optional agent scans a list of URLs in bulk, analyzes the results with Claude, and produces structured reports:

```bash
cd agent
cp urls.example.txt urls.txt
# edit urls.txt with targets you are authorized to scan
python -m pip install --require-hashes -r requirements.txt
export ANTHROPIC_API_KEY="sk-ant-..."
export SECURITY_SCANNER_API_TOKEN="a-secure-random-token-of-at-least-32-characters"
python agent.py
```

---

## Tests and verification

Each package can be checked from its own directory:

```bash
# Backend (115+ tests and typecheck)
cd backend && npm run typecheck && npm test && npm run build

# Frontend (Vitest and ESLint)
cd frontend && npm run lint && npm test && npm run build

# MCP server
cd mcp-server && npm run build -- --noEmit && npm run build

# Python agent
cd agent && python -c "import ast, pathlib; ast.parse(pathlib.Path('agent.py').read_text(encoding='utf-8'))"
```

---

## Repository layout

```text
.
├── backend/          # Express API, scanner engines, security policies, tests
├── frontend/         # React 19 + Vite user interface
├── mcp-server/       # Stdio Model Context Protocol server
├── agent/            # Autonomous Python analysis agent and sample target list
├── shared/           # Shared TypeScript type definitions
├── .env.example      # Environment variable template
├── .gitignore        # Hardened Git ignore rules
├── LICENSE           # GNU Affero General Public License v3.0 (AGPL-3.0)
└── README.md
```

Source comments and test names are written in Turkish.

---

## License

Released under the **GNU Affero General Public License v3.0 (AGPL-3.0)**. See [LICENSE](LICENSE) for details.
