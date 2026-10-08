# Secure Password Manager

A Java 17 and Spring Boot web application for storing website credentials in
an encrypted vault. It uses MariaDB for normal application runs and H2 only
for automated tests.

> **Learning project:** The server derives the vault key and encrypts/decrypts
> data while handling requests. This is not end-to-end encryption and has not
> been independently security-certified. Do not store real credentials in a
> public or untrusted deployment.

## Problem statement

Users often reuse or store website passwords insecurely. This project
demonstrates how to authenticate users, encrypt stored vault records, restrict
each user to their own entries, and provide basic password-health feedback.

## Features

- Account registration and Spring Security form login.
- Credential vault create, list, edit, delete, and unlock/lock flows.
- Password strength checker and secure browser-side password generator.
- Dashboard and vault security score with weak, reused, and old-password
  warnings.
- Audit records for registration, login outcomes, vault unlocks, and vault
  changes.

## Security design

- Master passwords are hashed with BCrypt using work factor 12; they are not
  used as the vault encryption key directly.
- A per-user random 32-byte salt and PBKDF2-HMAC-SHA256 (600,000 iterations)
  derive a 256-bit vault key from the master password.
- Each vault record is serialized and encrypted with AES-256-GCM using a new
  12-byte nonce. The authenticated additional data binds ciphertext to its
  owning user.
- The database stores the encrypted vault payload, not the plaintext site,
  username, or password. The application server decrypts the entry when the
  unlocked vault is used.
- Spring Security protects authenticated routes, enables CSRF protection,
  uses server-side sessions, migrates the session on authentication, and
  invalidates it on logout. The derived key is cleared on vault lock, logout,
  and session destruction.
- Five failed account-password or vault-unlock attempts trigger a 15-minute
  account lock. There is no separate IP-based rate limiter.
- Vault repository lookups include the authenticated owner's ID, returning
  not found for another user's entry.
- Request forms use Jakarta validation. Thymeleaf `th:text` output and normal
  escaped attribute binding prevent the tested stored/reflected XSS payloads
  from being emitted as executable markup.
- Spring Data JPA repository methods are used for database access; no
  user-provided SQL string concatenation is used in the application query
  paths reviewed.
- Response headers include a restrictive Content Security Policy,
  `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`,
  `Referrer-Policy: no-referrer`, and `Permissions-Policy`.
- Session cookies are HttpOnly and SameSite=Lax. The Secure flag is enabled
  with the production profile; local HTTP defaults it off.
- Database URL, username, and password are configured externally through
  environment variables. No encryption key or JWT secret is configured as an
  application secret; this project does not use JWT.

### Important limitations

- This is not end-to-end encryption: an application/server compromise or an
  active unlocked session can expose decrypted vault data.
- There is no IP-based rate limiting, MFA, password-reset/recovery flow,
  backup/recovery feature, or external breach-password check.
- A lost master password cannot be used to recover the encrypted vault.
- OWASP ZAP was not run for the recorded verification; no ZAP report is
  available. See [SECURITY_TESTING.md](./SECURITY_TESTING.md).
- HTTPS termination and production deployment infrastructure are not included.

## Technology stack

- Java 17
- Spring Boot 3.5.6
- Spring MVC, Spring Security, Spring Data JPA, Jakarta Validation
- Thymeleaf, HTML, CSS, JavaScript
- MariaDB (MySQL-compatible JDBC connection) for runtime persistence
- Flyway for schema migration
- H2 in-memory database for tests
- Maven

## Architecture overview

| Package | Responsibility |
|---|---|
| `config` | Spring Security and application configuration |
| `controller` | Web routes and MVC request handling |
| `dto` | Validated form and response objects |
| `model` | JPA entities |
| `repository` | Spring Data persistence queries |
| `security` | User authentication, handlers, and vault-session lifecycle |
| `service` | Authentication, encryption, vault, and security-report logic |

The browser submits forms to MVC controllers. Services apply validation,
authentication, owner checks, and cryptography; Spring Data JPA persists
records to MariaDB. Flyway owns the runtime schema.

## Database design

Flyway migration `V1__create_initial_schema.sql` creates:

- `users`: email, BCrypt password hash, unique vault KDF salt/settings,
  account-lock state, and timestamps.
- `vault_entries`: owner ID, encrypted payload, GCM nonce, version, and
  password-change/timestamp metadata.
- `audit_logs`: account/event references and timestamps; no credential values
  are intended to be recorded.
- `flyway_schema_history`: created and maintained by Flyway.

The application expects the database itself to exist before startup. Flyway
creates and tracks the application tables; Hibernate is configured to validate
their mappings rather than create or update the production schema.

## Configure local MariaDB

The verified local setup used XAMPP MariaDB at `127.0.0.1:3307`, database
`secure_password_manager`, and application user `spm_app`. The app expects:

| Environment variable | Purpose |
|---|---|
| `DB_URL` | JDBC URL (optional override; default points at localhost port 3306) |
| `DB_USERNAME` | Database user (default `spm_app`) |
| `DB_PASSWORD` | Database password (required; no source-config default) |
| `COOKIE_SECURE` | Optional local override for the session cookie Secure flag; defaults to `false`. The `prod` profile sets it to Secure. |

Create the database and application user using a MariaDB administrator
connection. Choose a strong database password locally; do not reuse the
master password. For an existing app user, set/reset its password as needed
and grant the listed schema permissions:

```sql
CREATE DATABASE IF NOT EXISTS secure_password_manager
    CHARACTER SET utf8mb4
    COLLATE utf8mb4_unicode_ci;

CREATE USER IF NOT EXISTS 'spm_app'@'localhost'
    IDENTIFIED BY 'choose-a-strong-database-password';
GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, ALTER, INDEX, REFERENCES
    ON secure_password_manager.* TO 'spm_app'@'localhost';
```

For PowerShell, set the values in the same window used to launch Maven. The
password is prompted for and is not part of the command text:

```powershell
$env:DB_URL = "jdbc:mysql://127.0.0.1:3307/secure_password_manager?serverTimezone=UTC"
$env:DB_USERNAME = "spm_app"
$secure = Read-Host "Enter the spm_app database password" -AsSecureString
$env:DB_PASSWORD = [System.Net.NetworkCredential]::new("", $secure).Password
```

Do not commit credentials, put them in `application.properties`, or paste
them into logs/issues. `.env` files are ignored by Git; Spring Boot does not
automatically load a `.env` file in this project.

## Run the application

Requirements: JDK 17, Maven, and a reachable MySQL-compatible MariaDB
instance with the database and app user configured above.

From the project root, after setting the environment variables:

```powershell
mvn.cmd spring-boot:run
```

If Maven is not on `PATH`, invoke its installed `mvn.cmd` by full path. On
startup, verify the log shows the intended MariaDB URL, Flyway migration
validation, and the Spring Boot `Started` message. The reported local
verification used MariaDB 10.4.32 on port 3307; Hibernate emitted a legacy
MySQL-compatible server-version warning, so this should not be interpreted as
support for every MariaDB release.

Open `http://localhost:8080` for local use. Local HTTP uses an insecure
session cookie by design. The `prod` profile enables the Secure cookie flag,
which requires HTTPS for browser sessions to be sent.

## Tests

Run the suite with:

```powershell
mvn.cmd test
```

Tests use H2 with the `test` profile and do not use the configured MariaDB
database. They cover authentication, encryption, owner isolation, CSRF,
XSS/SQL-injection input handling, lockout, response headers, and a real HTTP
session-expiry flow. Test fixtures contain synthetic credentials only.

## Verification record

The last recorded full Maven run completed with **26 tests: 26 passed, 0
failed, 0 skipped**. The local MariaDB application startup, Flyway schema
validation, registration/login, and vault operations were reported as manually
verified on the XAMPP database. Automated security regression tests and
separate local HTTP checks used H2, not MariaDB.

Manual local HTTP checks against a disposable H2-backed instance confirmed
SQL-like login rejection, escaped stored XSS output, reflected payload
handling, owner-scoped 404 responses, CSRF rejection, five-failure lockout,
logout invalidation, configured security headers, and generic malformed-route
errors. A real HTTP test confirmed session expiry using a one-minute test
override. This is not a ZAP scan, a full production penetration test, or a
security certification.

## Verified Resume Claims

> Built a Java 17 Spring Boot password manager with BCrypt password hashing,
> PBKDF2-derived AES-256-GCM vault encryption, owner-scoped access controls,
> account lockout, session protections, audit logging, and MariaDB persistence;
> verified the automated suite (26 passing tests) and local MariaDB startup
> and application flows.

## Future improvements

- Run and document an OWASP ZAP baseline/active scan in an authorized test
  environment and address reviewed findings.
- Add IP/account-aware throttling, MFA, secure password recovery, and
  operational alerting.
- Add production HTTPS/reverse-proxy configuration, backup/restore procedures,
  and deployment automation.
- Test against supported MariaDB versions and explicitly address Hibernate's
  legacy server-version warning.
- Improve vault-key lifecycle/rotation and add formal threat modeling,
  dependency scanning, and independent security review.
