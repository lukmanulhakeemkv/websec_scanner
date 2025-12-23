# Web Security Report for https://linkedmyclone.netlify.app

**Generated:** 2025-12-23T10:09:30.285466 UTC

**Scan duration:** 25.42 seconds


---

## 1) HTTP Security Headers

- **Content-Security-Policy**: Missing

- **Strict-Transport-Security**: max-age=31536000; includeSubDomains; preload

- **X-Frame-Options**: Missing

- **X-XSS-Protection**: Missing

- **X-Content-Type-Options**: Missing

- **Referrer-Policy**: Missing

- **Server**: Netlify

- **Content-Type**: text/html; charset=UTF-8


## 2) SSL/TLS Info

- Error: SSL/TLS check failed: _ssl.c:1059: The handshake operation timed out


## 3) Directory scan (safe list)

- No accessible entries from the safe wordlist were found.


## 4) Light SQLi indicator test (non-destructive)

- no query parameters to test


## 5) Open redirect quick check

- No open redirect discovered by the heuristic.


---

## Notes & Recommendations

- This tool performs light, non-destructive tests. For thorough testing, use authorized pentest tools and follow a test plan.

- Fix missing security headers (CSP, HSTS, etc.) where appropriate.

- Monitor certificate expiry and rotate before expiry.

- If sensitive files or directories were discovered, remove or restrict access and add proper access controls.
