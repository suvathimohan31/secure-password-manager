# OWASP Top 10 Security Test Plan

This document contains the test procedures and the results actually verified
for this local learning project. Run tests only against your own local
instance and disposable test accounts.

## Before testing

1. Start XAMPP MySQL and the Spring Boot application.
2. Use `http://localhost:8080` and create two disposable test accounts.
3. Add at least one test vault entry to the first account. Record its numeric
   entry ID from the URL when editing it. Do not use real credentials.
4. For ZAP checks, use OWASP ZAP only against this local application. Use the
   browser's proxy through ZAP or the ZAP Request Editor/Repeater to change
   request values. Do not run active scans against systems you do not own.
5. The rows below record the results actually obtained on 2026-10-08. Live
   HTTP checks used a disposable in-memory H2 database; the automated tests do
   not connect to the configured MySQL database. `BLOCKED` means that the
   corresponding MySQL, HTTPS deployment, or ZAP check could not be performed.

| ID | OWASP category | Test and exact steps | Expected secure result | Actual result | Pass/Fail |
|---|---|---|---|---|---|
| SQLi-1 | A03: Injection (SQL injection) | Open `/login`. In ZAP, capture the login POST and replace the email with `test' OR '1'='1` and the password with `' OR 1=1 -- `. A normal browser may block the malformed email because its field is `type=email`; replay the modified request through ZAP. Do not use a real account password. | Login is rejected with the normal generic failure response. No account is authenticated, no database error or SQL text is shown, and no records are changed. | Live HTTP against disposable H2: SQL-shaped login remained unauthenticated. Automated registration injection case also passed. ZAP was not run. | PASS (HTTP and automated; no ZAP) |
| SQLi-2 | A03: Injection (SQL injection) | Sign in and unlock the first test account's vault. In the website, username, and password fields, submit harmless SQL-looking text such as `' OR 1=1 -- ` and `'; SELECT 1; -- `. Save, view, edit, and delete only this test entry. | Inputs are treated as ordinary credential text; they do not change query behavior, expose other entries, or modify unrelated database records. The normal validation rules still apply. | Live HTTP against disposable H2: SQL-looking vault text was stored/displayed as text; no query effect observed. Automated DB check found no plaintext marker in encrypted payload. | PASS (HTTP and automated; MySQL not inspected) |
| XSS-1 | A03: Injection (cross-site scripting, stored) | While unlocked, create a test entry with a site or username value such as `<script>alert('stored-xss')</script>`. Save it, return to the list, then reopen the entry and dashboard. If testing using ZAP, send the same payload in the corresponding form field. | The value is displayed as inert text; no alert runs and no script executes on the list, edit page, or dashboard. | Live HTTP against disposable H2: stored payload appeared HTML-escaped (`&lt;script&gt;`); raw executable tag was absent. | PASS |
| XSS-2 | A03: Injection (cross-site scripting, reflected) | Open `/login?error=%3Cscript%3Ealert('reflected-xss')%3C%2Fscript%3E`. Also submit a harmless script-tag payload as the email on the login form. Observe the page and browser developer console. | The page does not execute attacker-supplied script. The login error remains generic, and supplied values are not inserted as executable HTML. | Live HTTP against disposable H2: reflected query payload was absent from response and no script tag appeared. Automated reflected-XSS test also passed. | PASS |
| IDOR-1 | A01: Broken Access Control (IDOR) | Sign in as test user A, create an entry, and record its edit URL, for example `/vault/123/edit`. Sign out. Sign in as test user B, unlock B's vault, and request A's exact edit URL. Also try A's delete URL by submitting a POST request to `/vault/123/delete` with B's authenticated session and a valid CSRF token (or use ZAP to replay the request). | User B cannot view, edit, or delete A's entry. The edit URL returns not found (404); the delete request does not delete the entry. A's entry remains accessible to A. | Live HTTP: user B received 404 for A's edit and delete URLs; A could still view the entry. Automated test also verified update returns 404. | PASS |
| CSRF-1 | A01: Broken Access Control (CSRF) | Sign in and unlock a test account. In browser developer tools or ZAP, capture the POST request for creating or deleting a test entry. Replay it after removing the `_csrf` form value / `X-CSRF-TOKEN` header, keeping the authenticated session cookie. | Spring Security rejects the request (typically 403). No vault entry is created, changed, or deleted. | Live HTTP: create POST without a token returned 403. Automated test confirmed no row was created. | PASS |
| AUTH-1 | A07: Identification and Authentication Failures (lockout) | Sign out. On `/login`, submit the correct test email and an incorrect password five times. Then attempt sign-in with the correct password before 15 minutes have elapsed. After the lock period, try the correct password again. | Failed login attempts are recorded. The account is locked after five failures and cannot sign in during the 15-minute lockout; it can sign in after the lock expires. No password or stack trace is displayed. | Live HTTP: five bad passwords caused the subsequent correct password to be refused. The 15-minute lockout expiry was not waited out. | PARTIAL (lockout verified; expiry release not verified) |
| AUTH-2 | A07: Identification and Authentication Failures (session timeout) | Sign in and unlock the vault. Do not send any requests for at least 16 minutes. Then open `/dashboard` and `/vault` in a fresh request (not from browser back/forward cache). | The expired authenticated session is no longer accepted and the user is redirected to login. The vault key is cleared when the HTTP session is destroyed. | Real embedded-container HTTP test: after 65 seconds idle with a one-minute test override, the request redirected to `/login`. Application configuration and integration test assert the normal 15-minute timeout; a full 16-minute idle period was not run. | PASS (expiry mechanism and configured value verified) |
| AUTH-3 | A07: Identification and Authentication Failures (logout/session invalidation) | Sign in and unlock the vault. Sign out using the app's **Sign out** button. In developer tools or ZAP, replay a previously captured authenticated request to `/dashboard` or `/vault` using the old session cookie. | The old session cookie no longer authenticates the request; the user is redirected to login. The vault key is cleared as part of logout/session invalidation. | Live HTTP replay of the old session cookie returned the login page. Automated test confirmed the session was invalidated and the stored vault key was zeroed. | PASS |
| CONFIG-1 | A05: Security Misconfiguration (response headers) | In browser developer tools, open Network, load `/login`, and inspect the response headers. Also inspect an authenticated `/dashboard` response. Check for `Content-Security-Policy`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY` (or equivalent CSP `frame-ancestors 'none'`), `Referrer-Policy: no-referrer`, and `Permissions-Policy`. | The responses include the configured restrictive CSP, anti-framing protection, `nosniff`, `no-referrer`, and the configured Permissions Policy. No permissive policy such as `unsafe-eval` is introduced. | Live HTTP `/login`: CSP present, `X-Frame-Options: DENY`, `nosniff`, `no-referrer`, and Permissions-Policy present. CSP did not contain `unsafe-eval`. | PASS |
| CONFIG-2 | A05: Security Misconfiguration (session cookie flags) | In developer tools Network or ZAP, inspect the `Set-Cookie` response after login. Check `JSESSIONID` for `HttpOnly`, `SameSite=Lax`, and `Secure`. For a production-like check, serve the app over HTTPS with `COOKIE_SECURE=true`, sign in, and inspect the cookie again. | `HttpOnly` and `SameSite=Lax` are present. With HTTPS and `COOKIE_SECURE=true`, `Secure` is present. Local plain-HTTP development may omit `Secure`; do not treat that local setting as deployment-safe. | Live local HTTP cookie had `HttpOnly` and `SameSite=Lax`; `Secure` was absent as expected for HTTP. Production-profile integration test checked emitted `Secure`; no deployed HTTPS endpoint was available. | PARTIAL (local and profile verified; deployed HTTPS not verified) |
| CONFIG-3 | A05: Security Misconfiguration (error information disclosure) | Request malformed and missing resources, for example `/vault/not-a-number/edit` and `/not-a-real-page`. If safely available in the local test environment, trigger a controlled server-side error and inspect the browser response. Do not intentionally break or expose a production service. | Error responses do not include stack traces, source paths, SQL statements, framework internals, or credentials. The application returns a generic client-facing error. | Live HTTP malformed path returned 400 with no exception, application path, stack trace, or SQL text. Automated error-response test also passed. | PASS |
| DATA-1 | A02: Cryptographic Failures (vault data at rest) | Create a test entry with a unique marker in its site, username, and password, for example `vault-marker-unique-493`. In phpMyAdmin, select `secure_password_manager` and run `SELECT id, user_id, HEX(encrypted_payload) AS ciphertext_hex, HEX(nonce) AS nonce_hex FROM vault_entries;`. Search the displayed hex/ciphertext for the marker, and confirm the entry can still be read only in the unlocked application. Do not export or share the result. | The database contains ciphertext and a nonce, not the marker or readable site, username, or password. Ciphertext is non-empty and the app can decrypt it after vault unlock. | Automated test inspected encrypted bytes in isolated H2 and found no plaintext marker. The user verified the app's MariaDB-backed vault operations and the schema tables; direct inspection of MySQL ciphertext contents was not recorded in this verification. | PARTIAL (H2 automated check; MariaDB operations user-verified, payload contents not inspected) |
| DATA-2 | A02: Cryptographic Failures (master password at rest) | Register a disposable test account. In phpMyAdmin, run `SELECT email, LEFT(password_hash, 4) AS hash_prefix, LENGTH(password_hash) AS hash_length FROM users;`. Do not query, copy, or share the complete password hash. | `hash_prefix` indicates BCrypt (commonly `$2a$`, `$2b$`, or `$2y$`), and the hash length is consistent with a BCrypt hash (normally 60 characters). The master password is not stored in plaintext. | Automated test inspected isolated H2 and confirmed BCrypt hash format and non-plaintext master password. MariaDB-backed registration was user-verified; direct inspection of the MariaDB password hash was not recorded. | PARTIAL (H2 automated check; MariaDB registration user-verified, hash contents not inspected) |

## Recording results

## Release verification notes

- `mvn test` ran 26 tests: 26 passed, 0 failed, 0 skipped. This includes 13
  OWASP integration tests, 1 real-HTTP session-expiry test, and 12 unit tests.
- Live HTTP security checks ran against `localhost` using a disposable
  in-memory H2 database; they did not use or alter MariaDB data.
- The user separately reported successful Spring Boot startup against XAMPP
  MariaDB at `127.0.0.1:3307`, Flyway schema validation at version 1, and
  registration/login/vault operations. The user also reported the four
  expected application/Flyway tables visible in phpMyAdmin. This does not
  constitute a direct inspection of stored password hashes or ciphertext.
- OWASP ZAP was not run. The official ZAP 2.17.0 archive download was blocked
  by endpoint protection before it could be verified or extracted. No ZAP
  scan or re-scan was performed, and `docs/zap-report.html` was not created.
- Direct database content inspection for password hashes/ciphertext, ZAP
  scanning, and deployment were not part of the live HTTP verification here.
- A local Git repository was initialized for the first commit; there was no
  pre-existing commit history or Git remote to inspect, so previous commits
  and GitHub state could not be checked. The staged source/config/docs scan
  found no deployment credentials, private keys, or environment files.
  `.env`, environment variants, build output, logs, and common key files are
  ignored. Two secret-like assignments in the staged scan were synthetic
  test-only password/crypto vectors, not deployment credentials.

These results describe only the checks listed here and are not a security
certification. ZAP, direct MySQL password/ciphertext inspection, GitHub-history,
and production HTTPS results remain unverified.
