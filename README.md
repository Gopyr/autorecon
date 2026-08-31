# AutoRecon
Toolkit kecil untuk recon dan web quick-audit.

## Tool 1: webaudit
Audit cepat headers, CORS, dan TLS.

Usage:
    python3 webaudit.py <url> [--timeout 10] [--output out.json]

Example:
    python3 webaudit.py https://example.com --output evidence/example.com.json
