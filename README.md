# AutoRecon

Toolkit kecil untuk recon dan web quick-audit.

## Tool 1: webaudit

Audit cepat headers, CORS, dan TLS dari target URL.

### Tujuan
- Deteksi cepat security headers yang missing
- Identifikasi konfigurasi CORS berisiko
- Cek versi TLS dan cipher suite

### Cara pakai
```bash
python3 webaudit.py <url> [--timeout 10] [--output out.json]
```

### Parameter
- `url` — target URL atau hostname (contoh: `https://example.com`)
- `--timeout` — timeout request dalam detik (default: 10)
- `--output` — path file output JSON report

### Contoh output
```json
{
  "timestamp": "2026-08-31 13:59:43 WIB",
  "target": "https://example.com:443/",
  "headers": {
    "date": "Mon, 31 Aug 2026 06:59:45 GMT",
    "content-type": "text/html",
    "server": "cloudflare"
  },
  "cors": {
    "acao": null,
    "acac": null,
    "vuln": false
  },
  "tls": {
    "version": "TLSv1.3",
    "cipher": ["TLS_AES_256_GCM_SHA384", "TLSv1.3", 256],
    "subject": {"commonName": "example.com"},
    "issuer": {"commonName": "Cloudflare TLS Issuing ECC CA 3"},
    "notBefore": "Jul 29 22:10:08 2026 GMT",
    "notAfter": "Oct 27 22:17:21 2026 GMT"
  },
  "findings": [
    "HSTS missing",
    "CSP missing",
    "X-Frame-Options missing",
    "XCTO missing",
    "Referrer-Policy missing",
    "Permissions-Policy missing"
  ]
}
```

### Arti temuan
- `HSTS missing` — header `Strict-Transport-Security` tidak ada
- `CSP missing` — header `Content-Security-Policy` tidak ada
- `X-Frame-Options missing` — tidak ada proteksi terhadap clickjacking
- `XCTO missing` — tidak ada `X-Content-Type-Options: nosniff`
- `CORS wildcard (*)` — `Access-Control-Allow-Origin: *` berisiko
- `Weak TLS` — versi TLS di bawah 1.2
