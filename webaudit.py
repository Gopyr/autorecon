#!/usr/bin/env python3
"""
WebAudit — Quick headers/CORS/TLS audit.
Usage:
    python3 webaudit.py <url> [--timeout 10] [--output out.txt]

Output:
    - Prints audit summary to stdout
    - Saves full report to --output if provided
"""
import argparse, json, socket, ssl, sys
from urllib.parse import urlparse
import requests
from datetime import datetime, timezone, timedelta

DEFAULT_TIMEOUT = 10

def now_wib():
    return datetime.now(timezone(timedelta(hours=7))).strftime('%Y-%m-%d %H:%M:%S WIB')

def parse_target(raw):
    raw = raw.strip()
    if not raw.startswith(('http://', 'https://')):
        raw = 'https://' + raw
    p = urlparse(raw)
    host = p.hostname
    port = p.port or (443 if p.scheme == 'https' else 80)
    scheme = p.scheme
    path = p.path or '/'
    return scheme, host, port, path

def http_get(url, timeout=DEFAULT_TIMEOUT):
    try:
        r = requests.get(url, timeout=timeout, allow_redirects=False, verify=True)
        return r
    except requests.exceptions.SSLError as e:
        return {'error': f'SSL error: {e}'}
    except Exception as e:
        return {'error': str(e)}

def tls_info(host, port=443, timeout=DEFAULT_TIMEOUT):
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                version = ssock.version()
                return {
                    'version': version,
                    'cipher': cipher,
                    'subject': dict(x[0] for x in cert.get('subject', ())),
                    'issuer': dict(x[0] for x in cert.get('issuer', ())),
                    'notBefore': cert.get('notBefore'),
                    'notAfter': cert.get('notAfter'),
                }
    except Exception as e:
        return {'error': str(e)}

def audit(url, timeout=DEFAULT_TIMEOUT):
    scheme, host, port, path = parse_target(url)
    target = f"{scheme}://{host}:{port}{path}"
    report = {
        'timestamp': now_wib(),
        'target': target,
        'headers': {},
        'cors': {},
        'tls': {},
        'findings': [],
    }

    # HTTP request
    resp = http_get(target, timeout=timeout)
    if isinstance(resp, dict) and 'error' in resp:
        report['findings'].append(f"HTTP error: {resp['error']}")
        return report

    headers = {k.lower(): v for k, v in resp.headers.items()}
    report['headers'] = dict(headers)

    # Security headers
    sec_checks = {
        'strict-transport-security': 'HSTS missing',
        'content-security-policy': 'CSP missing',
        'x-frame-options': 'X-Frame-Options missing',
        'x-content-type-options': 'XCTO missing',
        'referrer-policy': 'Referrer-Policy missing',
        'permissions-policy': 'Permissions-Policy missing',
    }
    for h, msg in sec_checks.items():
        if h not in headers:
            report['findings'].append(msg)

    # CORS
    acao = headers.get('access-control-allow-origin')
    acac = headers.get('access-control-allow-credentials')
    report['cors'] = {
        'acao': acao,
        'acac': acac,
        'vuln': False,
    }
    if acao == '*':
        report['cors']['vuln'] = True
        report['findings'].append('CORS wildcard (*)')
    if acao == '*' and acac == 'true':
        report['cors']['vuln'] = True
        report['findings'].append('CORS wildcard + credentials')

    # TLS
    if scheme == 'https':
        tls = tls_info(host, port, timeout)
        report['tls'] = tls
        if 'error' not in tls:
            if tls.get('version') not in ('TLSv1.2', 'TLSv1.3'):
                report['findings'].append(f"Weak TLS: {tls.get('version')}")
        else:
            report['findings'].append(f"TLS error: {tls['error']}")

    return report

def main():
    parser = argparse.ArgumentParser(description='WebAudit — headers/CORS/TLS quick audit')
    parser.add_argument('url', help='Target URL or hostname')
    parser.add_argument('--timeout', type=int, default=DEFAULT_TIMEOUT)
    parser.add_argument('--output', default='')
    args = parser.parse_args()

    report = audit(args.url, timeout=args.timeout)
    out = json.dumps(report, indent=2, default=str)
    print(out)

    if args.output:
        with open(args.output, 'w') as f:
            f.write(out)
        print(f"\n[+] Report saved to {args.output}")

if __name__ == '__main__':
    main()
