# Vulnerabilities Catalog

> All findings are intentional for training. OWASP Top 10 2021 mapping included.

## 1) IDOR on Issue Editing
- **OWASP:** A01 Broken Access Control
- **File:** `app/main.py`
- **Snippet:** `conn.execute("UPDATE issues SET ... WHERE id=?", (..., issue_id))`
- **Why:** No ownership/role check.
- **Exploit:** POST `/issues/2/edit` as low-priv user.
- **Impact:** Unauthorized modification.
- **Secure fix:** Verify current user owns issue or is admin.

## 2) Admin Panel Missing Authorization
- **OWASP:** A01
- **File:** `app/main.py`
- **Snippet:** `/admin` endpoint fetches users/issues directly.
- **Exploit:** Visit `/admin` unauthenticated.
- **Impact:** Sensitive data exposure.
- **Fix:** Enforce authenticated admin role.

## 3) Direct Object Reference in File Download + Traversal
- **OWASP:** A01
- **File:** `app/main.py`
- **Snippet:** `FileResponse(f"uploads/{name}")`
- **Exploit:** `/download?name=../backup.sql`
- **Impact:** Arbitrary file read.
- **Fix:** Normalize path + per-object access checks.

## 4) Cryptographic Failures
- **OWASP:** A02
- **File:** `app/auth.py`, `app/config.py`
- **Snippet:** MD5 hash, `SECRET_KEY = "supersecret"`
- **Exploit:** Offline cracking / forged sessions.
- **Impact:** Account compromise.
- **Fix:** Argon2/bcrypt + rotated env secrets.

## 5) SQL Injection (Login/Search/API)
- **OWASP:** A03 Injection
- **File:** `app/main.py`
- **Snippet:** f-strings in SQL queries.
- **Exploit:** `' OR 1=1 --`
- **Impact:** Auth bypass/data exfiltration.
- **Fix:** Parameterized queries.

## 6) Command Injection
- **OWASP:** A03
- **File:** `app/main.py`
- **Snippet:** `subprocess.getoutput(cmd)`
- **Exploit:** `/cmd?cmd=id;cat /etc/passwd`
- **Impact:** RCE.
- **Fix:** Remove endpoint or strict allowlist.

## 7) Template Injection
- **OWASP:** A03
- **File:** `app/main.py`
- **Snippet:** `Template(name).render()`
- **Exploit:** `/render?name={{7*7}}`
- **Impact:** Data exposure/code execution path.
- **Fix:** Never render user-provided templates.

## 8) Insecure Design (No Rate Limits / Logic flaws)
- **OWASP:** A04
- **File:** whole app
- **Snippet:** no lockout/rate limit flow.
- **Exploit:** brute-force login/reset abuse.
- **Impact:** Account takeover.
- **Fix:** Add throttling and abuse protections.

## 9) Security Misconfiguration
- **OWASP:** A05
- **File:** `app/config.py`, `app/main.py`
- **Snippet:** `DEBUG=True`, CORS `*`, verbose exceptions.
- **Exploit:** Trigger errors to read stack details.
- **Impact:** Recon for attackers.
- **Fix:** Harden production settings.

## 10) Vulnerable Components
- **OWASP:** A06
- **File:** `requirements.txt`
- **Snippet:** `fastapi==0.65.2`
- **Exploit:** known CVEs in outdated libs.
- **Impact:** Increased exploit surface.
- **Fix:** upgrade/pin maintained versions.

## 11) Identification & Authentication Failures
- **OWASP:** A07
- **File:** `app/main.py`, `app/auth.py`
- **Snippet:** no lockout, session fixation, predictable reset token, enumeration.
- **Exploit:** fixed session cookie + login.
- **Impact:** Session hijack/account takeover.
- **Fix:** rotate session IDs, opaque reset tokens.

## 12) Software & Data Integrity Failures
- **OWASP:** A08
- **File:** `app/main.py`
- **Snippet:** `pickle.loads(...)`, unrestricted upload.
- **Exploit:** malicious pickle payload.
- **Impact:** RCE.
- **Fix:** ban unsafe deserialization, validate files.

## 13) Logging & Monitoring Failures
- **OWASP:** A09
- **File:** design-level
- **Snippet:** failed logins/admin actions not fully audited.
- **Exploit:** stealthy attacks evade detection.
- **Impact:** delayed incident response.
- **Fix:** comprehensive security event logging + alerting.

## 14) SSRF
- **OWASP:** A10
- **File:** `app/main.py`
- **Snippet:** `requests.get(url)` from user input.
- **Exploit:** `/fetch?url=http://169.254.169.254/latest/meta-data/`
- **Impact:** internal network metadata access.
- **Fix:** block internal ranges + allowlist.

## Additional Deliberate Vulnerabilities
- Stored XSS: comments and issue description rendered with `|safe`.
- Reflected XSS: query in search input.
- DOM XSS: `location.hash` inserted with `innerHTML` in `home.html`.
- CSRF: all state-changing forms have no CSRF tokens.
- Clickjacking: no anti-framing headers.
- Open redirect: `/redirect?next=...`.
- Race condition: simultaneous edits/deletes have no locking/versioning.
- Mass assignment: role and owner_id accepted from untrusted input.
- Hardcoded admin credentials: in DB init and docs.
- Exposed backup: `backup.sql` and `/backup.sql` route.
- API keys in JS: `app/static/js/app.js`.
- Hidden route: `/superadmin`.
- robots.txt disclosure: `app/static/robots.txt`.
