import argparse
import concurrent.futures
import socket
import ssl
import time
import urllib.parse
from datetime import datetime
from typing import Dict, List, Tuple

import requests
from bs4 import BeautifulSoup

# ---- Config ----
REQUIRED_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-XSS-Protection",
    "X-Content-Type-Options",
    "Referrer-Policy",
]

SQL_ERROR_KEYWORDS = ["sql", "mysql", "syntax", "database", "odbc", "sqlite", "mariadb", "pg_"]


# ---- Utility functions ----
def normalize_url(url: str) -> str:
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url.rstrip("/")


def get_hostname_from_url(url: str) -> str:
    return urllib.parse.urlparse(url).hostname


# ---- Header scanner ----
def check_headers(url: str, timeout: int = 10) -> Dict[str, str]:
    try:
        r = requests.get(url, timeout=timeout, allow_redirects=True, headers={"User-Agent": "websec_scanner/1.0"})
        headers = {k: v for k, v in r.headers.items()}
        results = {}
        for h in REQUIRED_HEADERS:
            results[h] = headers.get(h, "Missing")
        # also capture server header and content-type
        results["Server"] = headers.get("Server", "Missing")
        results["Content-Type"] = headers.get("Content-Type", "Missing")
        return results
    except Exception as e:
        return {"error": f"Header check failed: {e}"}


# ---- SSL/TLS checker ----
def ssl_info(hostname: str, port: int = 443, timeout: int = 8) -> Dict[str, str]:
    info = {}
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(socket.AF_INET), server_hostname=hostname) as s:
            s.settimeout(timeout)
            s.connect((hostname, port))
            cert = s.getpeercert()
            # parse dates
            not_before = cert.get("notBefore")
            not_after = cert.get("notAfter")
            info["subject"] = dict(x[0] for x in cert.get("subject", ()))
            info["issuer"] = dict(x[0] for x in cert.get("issuer", ()))
            info["not_before"] = not_before
            info["not_after"] = not_after
            # compute days left if possible
            try:
                dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                info["days_until_expiry"] = (dt - datetime.utcnow()).days
            except Exception:
                info["days_until_expiry"] = "unknown"
            return info
    except Exception as e:
        return {"error": f"SSL/TLS check failed: {e}"}


# ---- Safe directory scan (non-destructive) ----
def check_path(url_base: str, path: str, timeout: int = 6) -> Tuple[str, int, str]:
    # returns (checked_url, status_code, reason snippet)
    target = f"{url_base.rstrip('/')}/{path.lstrip('/')}"
    try:
        r = requests.get(target, timeout=timeout, allow_redirects=True, headers={"User-Agent": "websec_scanner/1.0"})
        reason = r.reason
        # small snippet if body is small
        snippet = r.text[:300].strip().replace("\n", " ") if r.text else ""
        return target, r.status_code, snippet
    except Exception as e:
        return target, 0, f"error: {e}"


def directory_scan(url_base: str, wordlist: List[str], max_workers: int = 5, delay: float = 0.2) -> List[Tuple[str, int, str]]:
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = []
        for p in wordlist:
            futures.append(ex.submit(check_path, url_base, p))
            time.sleep(delay)  # gentle throttle
        for fut in concurrent.futures.as_completed(futures):
            results.append(fut.result())
    return results


# ---- Light SQLi indicator (safe) ----
def test_sqli_light(url: str, timeout: int = 8) -> Dict[str, str]:
    # This is intentionally non-exploitative: append a single quote to each query param and
    # look for database error strings. Do NOT send payloads or heavy exploitation triggers.
    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qsl(parsed.query)
    findings = []
    if not qs:
        return {"info": "no query parameters to test"}
    for k, v in qs:
        new_qs = qs.copy()
        # set this parameter with an extra quote
        new_qs = [(kk, (vv + "'" if kk == k else vv)) for kk, vv in qs]
        new_query = urllib.parse.urlencode(new_qs)
        test_url = urllib.parse.urlunparse(parsed._replace(query=new_query))
        try:
            r = requests.get(test_url, timeout=timeout, allow_redirects=True, headers={"User-Agent": "websec_scanner/1.0"})
            body = r.text.lower()
            if any(err in body for err in SQL_ERROR_KEYWORDS):
                findings.append({"param": k, "tested_url": test_url, "evidence": "db error-like text found"})
        except Exception as e:
            findings.append({"param": k, "tested_url": test_url, "error": str(e)})
    return {"findings": findings}


# ---- Basic open-redirect heuristic ----
def test_open_redirect(url: str, param_name: str = "next", timeout: int = 8) -> Dict[str, str]:
    parsed = urllib.parse.urlparse(url)
    qs = dict(urllib.parse.parse_qsl(parsed.query))
    qs[param_name] = "http://example.com/"
    new_query = urllib.parse.urlencode(qs)
    test_url = urllib.parse.urlunparse(parsed._replace(query=new_query))
    try:
        r = requests.get(test_url, timeout=timeout, allow_redirects=False, headers={"User-Agent": "websec_scanner/1.0"})
        if r.is_redirect or r.status_code in (301, 302, 303, 307, 308):
            loc = r.headers.get("Location", "")
            if loc and "example.com" in loc:
                return {"vulnerable": True, "tested_url": test_url, "redirect_location": loc}
        return {"vulnerable": False, "tested_url": test_url}
    except Exception as e:
        return {"error": str(e), "tested_url": test_url}


# ---- Report generation ----
def generate_markdown_report(output_path: str,
                             target_url: str,
                             header_results,
                             ssl_results,
                             dir_results,
                             sqli_results,
                             redirect_results,
                             start_time: float,
                             end_time: float):
    dur = end_time - start_time
    lines = []
    lines.append(f"# Web Security Report for {target_url}\n")
    lines.append(f"**Generated:** {datetime.utcnow().isoformat()} UTC\n")
    lines.append(f"**Scan duration:** {dur:.2f} seconds\n")
    lines.append("\n---\n")

    lines.append("## 1) HTTP Security Headers\n")
    if isinstance(header_results, dict) and "error" in header_results:
        lines.append(f"- Error: {header_results['error']}\n")
    else:
        for k, v in header_results.items():
            lines.append(f"- **{k}**: {v}\n")

    lines.append("\n## 2) SSL/TLS Info\n")
    if isinstance(ssl_results, dict) and "error" in ssl_results:
        lines.append(f"- Error: {ssl_results['error']}\n")
    else:
        lines.append(f"- Subject: {ssl_results.get('subject')}\n")
        lines.append(f"- Issuer: {ssl_results.get('issuer')}\n")
        lines.append(f"- Not before: {ssl_results.get('not_before')}\n")
        lines.append(f"- Not after: {ssl_results.get('not_after')}\n")
        lines.append(f"- Days until expiry: {ssl_results.get('days_until_expiry')}\n")

    lines.append("\n## 3) Directory scan (safe list)\n")
    found_any = False
    for url_c, status, snippet in dir_results:
        if status == 200:
            found_any = True
            lines.append(f"- **Found**: {url_c} (HTTP 200)\n  - snippet: `{snippet[:200]}`\n")
        elif status in (301, 302):
            lines.append(f"- Redirect: {url_c} (HTTP {status})\n")
        elif status == 403:
            lines.append(f"- Forbidden (403): {url_c}\n")
        elif status == 0:
            lines.append(f"- Error checking {url_c}: {snippet}\n")
    if not found_any:
        lines.append("- No accessible entries from the safe wordlist were found.\n")

    lines.append("\n## 4) Light SQLi indicator test (non-destructive)\n")
    if isinstance(sqli_results, dict) and "info" in sqli_results:
        lines.append(f"- {sqli_results['info']}\n")
    else:
        if sqli_results.get("findings"):
            for f in sqli_results["findings"]:
                lines.append(f"- Possible issue on param `{f.get('param')}`; tested URL: {f.get('tested_url')}\n  - evidence: {f.get('evidence','')}\n")
        else:
            lines.append("- No SQL error-like strings found in tested parameter variations.\n")

    lines.append("\n## 5) Open redirect quick check\n")
    if isinstance(redirect_results, dict) and redirect_results.get("vulnerable"):
        lines.append(f"- Potential open redirect: {redirect_results.get('tested_url')} -> {redirect_results.get('redirect_location')}\n")
    else:
        lines.append("- No open redirect discovered by the heuristic.\n")

    lines.append("\n---\n")
    lines.append("## Notes & Recommendations\n")
    lines.append("- This tool performs light, non-destructive tests. For thorough testing, use authorized pentest tools and follow a test plan.\n")
    lines.append("- Fix missing security headers (CSP, HSTS, etc.) where appropriate.\n")
    lines.append("- Monitor certificate expiry and rotate before expiry.\n")
    lines.append("- If sensitive files or directories were discovered, remove or restrict access and add proper access controls.\n")

    with open(output_path, "w", encoding="utf8") as f:
        f.write("\n".join(lines))

    return output_path


# ---- Main CLI ----
def main():
    parser = argparse.ArgumentParser(description="websec_scanner - safe website checklist scanner")
    parser.add_argument("target", help="Target site URL (e.g., https://example.com/path?x=1)")
    parser.add_argument("--wordlist", default="wordlist.txt", help="Path to small safe wordlist")
    parser.add_argument("--output", default="report.md", help="Markdown report path")
    parser.add_argument("--no-ssl", action="store_true", help="Skip SSL/TLS check")
    parser.add_argument("--max-workers", type=int, default=5, help="Max concurrent workers for directory scan")
    parser.add_argument("--delay", type=float, default=0.2, help="Delay between directory requests (seconds)")
    parser.add_argument("--open-redirect-param", default="next", help="Parameter name to use in open-redirect heuristic")
    args = parser.parse_args()

    target = normalize_url(args.target)
    start = time.time()
    # use origin (scheme + netloc) for safe directory scanning, not the full path/query
    parsed_target = urllib.parse.urlparse(target)
    base_origin = urllib.parse.urlunparse(parsed_target._replace(path="", params="", query="", fragment=""))
    print(f"[+] Target: {target}")
    print(f"[+] Base origin for directory scan: {base_origin}")

    print("[*] Running header check...")
    headers = check_headers(target)

    ssl_res = {}
    if not args.no_ssl:
        hostname = get_hostname_from_url(target)
        if hostname:
            print("[*] Running SSL/TLS check...")
            ssl_res = ssl_info(hostname)
        else:
            ssl_res = {"error": "Could not parse hostname"}
    else:
        ssl_res = {"info": "skipped by flag"}

    print("[*] Loading wordlist...")
    try:
        with open(args.wordlist, "r", encoding="utf8") as wf:
            wl = [l.strip() for l in wf if l.strip() and not l.startswith("#")]
    except FileNotFoundError:
        print("[-] Wordlist not found; skipping directory scan.")
        wl = []

    dir_results = []
    if wl:
        print("[*] Running directory scan (safe mode)...")
        dir_results = directory_scan(base_origin, wl, max_workers=args.max_workers, delay=args.delay)
    else:
        print("[*] No wordlist -> skipping directory checks.")

    print("[*] Running light SQLi indicator test...")
    sqli_res = test_sqli_light(target)

    print("[*] Running simple open-redirect heuristic...")
    redirect_res = test_open_redirect(target, param_name=args.open_redirect_param)

    end = time.time()
    print(f"[+] Generating report to {args.output}")
    generate_markdown_report(args.output, target, headers, ssl_res, dir_results, sqli_res, redirect_res, start, end)
    print("[+] Done. Review the report and act only with authorization.")


if __name__ == "__main__":
    main()