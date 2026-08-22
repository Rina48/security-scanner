# Contributing

Thanks for taking a look. This document covers how to get the project running locally, what the code standards are, and how changes are expected to land.

## Repository layout

The repo holds four independent packages plus a shared type module:

| Path | What it is | Runtime |
| --- | --- | --- |
| `backend/` | Express API, scanner engines, egress policy, SQLite history | Node.js >= 20 |
| `frontend/` | React 19 + Vite user interface | Node.js >= 20 |
| `mcp-server/` | Stdio Model Context Protocol server | Node.js >= 20 |
| `agent/` | Autonomous Python analysis agent | Python 3.11+ |
| `shared/` | TypeScript types used by backend and frontend | — |

Each Node package has its own `package.json` and is installed separately. There is no workspace root.

## Local setup

```bash
cp .env.example .env
```

Backend:

```bash
cd backend
npm ci
export SECURITY_SCANNER_API_TOKEN="a-secure-random-token-of-at-least-32-characters"
export SECURITY_SCANNER_ALLOWED_ORIGINS="http://127.0.0.1:5173"
npm run dev
```

Frontend, in a second terminal:

```bash
cd frontend
npm ci
npm run dev -- --host 127.0.0.1
```

On Windows PowerShell, use `Copy-Item` instead of `cp` and `$env:VAR = "value"` instead of `export`.

## Running the checks

CI runs four jobs, one per package. Run the matching command before opening a pull request:

```bash
cd backend    && npm run typecheck && npm test && npm run build
cd frontend   && npm run lint && npm test && npm run build
cd mcp-server && npm run build
cd agent      && python -c "import ast, pathlib; ast.parse(pathlib.Path('agent.py').read_text(encoding='utf-8'))"
```

A pull request that fails any of these will not be merged.

## Code standards

- **TypeScript everywhere on the Node side.** No `any` unless there is a comment explaining why it cannot be avoided.
- **Styling is vanilla CSS with design tokens.** Tokens live in the frontend's style files; do not introduce a CSS framework or inline style objects.
- **Types shared between backend and frontend belong in `shared/`.** Do not duplicate a type across two packages.
- **Source comments and test names are written in Turkish.** Keep new ones consistent with the surrounding file rather than mixing languages inside one module.

## Security rules for contributors

This project scans network targets, so some changes carry more weight than usual:

- Active scanning permission is decided by the backend's `ALLOWED_ACTIVE_HOSTS` allowlist. Never move that decision to client input, a request body, or a query parameter.
- The egress policy is fail-closed. If you add a new outbound request path, it must go through the existing SSRF, DNS pinning, and metadata IP filters.
- Do not raise the resource caps in `.env.example` as a convenience for a test. Override them locally instead.
- Never commit a real target list, scan report, or credential. `reports/`, `samples/`, and `agent/urls.txt` are gitignored for this reason.

## Commits and pull requests

Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add cookie prefix check to passive scanner
fix: reject redirect to link-local address
chore: bump express to 4.21
docs: document MCP tool arguments
test: cover expired certificate path
```

For a pull request:

1. Branch off `main`.
2. Keep one logical change per pull request.
3. Run the checks for every package you touched.
4. Describe what changed and why. If it affects scanning behavior, say what a user would observe differently.

## Reporting a vulnerability

Do not open a public issue for a security problem. See [SECURITY.md](SECURITY.md).
