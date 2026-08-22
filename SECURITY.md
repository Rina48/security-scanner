# Security Policy

## Reporting a vulnerability

Do not open a public issue for a security problem.

Use GitHub's private vulnerability reporting instead: go to the [Security tab](https://github.com/Rina48/security-scanner/security) and choose **Report a vulnerability**. The report stays private between you and the maintainer until a fix is available.

Please include:

- What the issue is and which package it affects (`backend`, `frontend`, `mcp-server`, or `agent`)
- Steps to reproduce, ideally with a minimal request or configuration
- What an attacker gains from it
- The commit or version you tested against

You can expect a first response within seven days. If the report is confirmed, the fix and a note about it will land on `main`, and you will be credited in the commit unless you ask otherwise.

## Supported versions

This project has no tagged releases yet. Only the current `main` branch receives fixes.

## In scope

- Authentication bypass on any route other than `/api/health`
- Any path that lets the scanner send a request to a host outside `ALLOWED_ACTIVE_HOSTS` when active scanning is requested
- SSRF bypasses: DNS rebinding, redirect chains, IP encoding tricks, or link-local and cloud metadata addresses reaching the fetch layer
- Leaking a scan target, token, or response body into logs, reports, or the SQLite history in a way the redaction layer should have caught
- Resource limit bypasses that let one scan exceed the configured request, byte, or concurrency caps
- Command or SQL injection in any package
- Vulnerabilities in the MCP server that let a connected LLM client escape the same restrictions the HTTP API enforces

## Out of scope

- Exposing the backend on a public interface. It binds to `127.0.0.1` by default and is not designed to be internet-facing; running it otherwise is a deployment choice, not a vulnerability.
- Running the tool against a target you are not authorized to test. That is a misuse of the tool, and it is prohibited by the README.
- Findings the scanner reports about a third-party site. Those belong to that site's owner, not to this project.
- Missing hardening on the test fixtures in `backend/test-fixtures/`. Those certificates and keys are generated for `localhost` tests and are intentionally public.
- Denial of service achieved by setting the resource limit environment variables to unreasonable values yourself.

## A note on what this tool proves

Security Scanner supports a review. A clean report does not mean a system is secure, and the project makes no such claim. Do not treat its output as a certification.
