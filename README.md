# AI-Assisted Software Engineering System — Audit Log Service

A tamper-evident, append-only audit log service backend prototype built with **Java 21**, **Spring Boot 3.x**, and **MySQL 8**.

## Project Purpose

The primary objective of this service is to provide an immutable, cryptographically verifiable, append-only audit logging mechanism for sensitive operations within enterprise systems. The service ensures data integrity through cryptographic hash chaining, supports structured redaction without breaking chain integrity, enforces retention policies, and provides rich filtering, pagination, and export capabilities.

## Technology Stack

- **Runtime & Language**: Java 21 LTS
- **Framework**: Spring Boot 3.3.3
- **Data Persistence**: Spring Data JPA / Hibernate
- **Database**: MySQL 8 (local installation; no Docker)
- **Validation**: Jakarta Bean Validation API
- **API Documentation**: Springdoc OpenAPI 2.x (Swagger UI)
- **Utilities**: Project Lombok
- **Testing**: JUnit 5, Mockito, Spring Boot Test Starter
- **Build Tool**: Apache Maven

## Project Structure

```text
com.example.auditlog
├── controller    # REST API endpoints & request routing
├── service       # Core business logic & interfaces
├── repository    # Spring Data JPA repositories & database access
├── entity        # JPA domain models / database entities
├── dto           # Data Transfer Objects for API requests/responses
├── exception     # Custom exception classes & global exception handlers
├── config        # Spring configurations (OpenAPI, security, etc.)
└── util          # Helper utilities (hashing, canonicalization, etc.)
```

## Local Setup & Configuration

### Prerequisites
- **Java Development Kit (JDK)** 21 installed and configured on your `PATH`.
- **Apache Maven** 3.9+ installed.
- **MySQL 8 Server** installed and running locally on `localhost:3306`.

### Database Preparation

Ensure the target database exists in your local MySQL instance:

```sql
CREATE DATABASE IF NOT EXISTS auditdb CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
```

### Environment Variables

Database credentials and host parameters are supplied securely via environment variables. Never commit actual passwords to version control.

| Environment Variable | Description | Default / Example Value | Required |
| :--- | :--- | :--- | :--- |
| `DB_USERNAME` | Local MySQL username | `your_mysql_username` (e.g., `root`) | **Yes** |
| `DB_PASSWORD` | Local MySQL password | `your_mysql_password` | **Yes** |
| `DB_HOST` | MySQL server host | `localhost` | No |
| `DB_PORT` | MySQL server port | `3306` | No |
| `DB_NAME` | MySQL database name | `auditdb` | No |
| `DB_URL` | Override full JDBC URL | *(Derived from host/port/name)* | No |
| `PORT` | Application HTTP server port | `8080` | No |
| `JPA_DDL_AUTO` | Hibernate DDL mode | `update` | No |
| `SHOW_SQL` | Log SQL queries | `false` | No |

### Setting Environment Variables Locally

#### Windows (PowerShell)
```powershell
$env:DB_USERNAME="<your_username>"
$env:DB_PASSWORD="<your_password>"
```

#### Windows (Command Prompt)
```cmd
set DB_USERNAME=<your_username>
set DB_PASSWORD=<your_password>
```

#### macOS / Linux (Bash / Zsh)
```bash
export DB_USERNAME="<your_username>"
export DB_PASSWORD="<your_password>"
```

---

## Build & Run

1. **Compile and Run Tests** (verifies local MySQL connectivity):
   ```bash
   mvn clean test
   ```

2. **Run Application**:
   ```bash
   mvn spring-boot:run
   ```

3. **Access API Documentation (Swagger UI)**:
   Once the application is running, open:
   [http://localhost:8080/swagger-ui.html](http://localhost:8080/swagger-ui.html)

   **How to Test via Swagger UI:**
   - **When using the dev profile:** The Swagger UI loads without credentials. When you click **Try it out** and **Execute** on any protected endpoint (like /audit/events), your web browser will intercept the 401 Unauthorized response and present a native pop-up prompting for a Username and Password. Enter admin / admin (or your configured DEV_USER / DEV_PASSWORD) to execute the request.
   - **When using the prod profile:** Swagger UI does not natively prompt for OIDC Bearer tokens. To test the prod profile via Swagger UI, you will need to use a browser extension (like ModHeader) to manually inject the Authorization: Bearer <your-jwt> header, or test the endpoints using Postman / cURL.

## Security & Profiles

This application requires security to access the APIs. The security implementation is profile-driven:

### Development Profile (--spring.profiles.active=dev)
- **Security Strategy**: HTTP Basic Authentication
- **Credentials**: Uses environment variables ${DEV_USER} and ${DEV_PASSWORD} (defaults to admin/admin if unset).
- **CORS**: Allows requests from ${DEV_ALLOWED_ORIGINS} (defaults to http://localhost:3000,http://localhost:8080).
- **Rate Limiting**: 100 requests per minute per authenticated principal/IP.

### Production Profile (--spring.profiles.active=prod)
- **Security Strategy**: JWT / OAuth2 Resource Server (No Basic Auth).
- **OIDC Configuration**: You must set ${OIDC_ISSUER_URI} and ${OIDC_AUDIENCE} in your environment. Spring Security performs issuer/JWK discovery during application initialization. The application therefore requires connectivity to the configured OIDC issuer/JWK discovery endpoint when initializing the JWT decoder. Once the signing keys are available/cached, individual JWT signature validation does not require a network call for every request. A fully air-gapped environment would require a different key-management/configuration approach and is outside this prototype's scope.
- **CORS**: STRICTLY requires ${PROD_ALLOWED_ORIGINS} environment variable. Unrestricted * is not supported.
- **Rate Limiting**: 1000 requests per minute.

> [!WARNING]
> The rate limiter (Bucket4j) is strictly in-memory and per-instance. It is not distributed across a cluster.

## Testing & Code Coverage

This project uses **JaCoCo** to track test coverage across the application. 

To execute the entire test suite (Unit, Integration, and Security tests) and generate the coverage report, run:

```bash
mvn clean verify
```

**How to view the JaCoCo coverage report:**
1. After the Maven command completes successfully, navigate to the newly generated `target` directory.
2. Open the file located at: `target/site/jacoco/index.html`
3. You can simply double-click the `index.html` file to open it in your web browser (Chrome, Edge, Firefox, etc.).
4. The web dashboard will provide a comprehensive breakdown of Instruction, Branch, and Line coverage per package and class.

## API Overview

### 1. Create Audit Event
Record a new event into the append-only ledger.
```bash
curl -X POST http://localhost:8080/audit/events \
  -H "Content-Type: application/json" \
  -d '{
    "eventType": "LOGIN_SUCCESS",
    "actorId": "user-123",
    "resourceType": "SYSTEM",
    "resourceId": "auth-server",
    "payload": {"ip": "192.168.1.50"}
  }'
```

### 2. Query Audit Events
Retrieve audit events with optional filtering and pagination.
```bash
curl -X GET "http://localhost:8080/audit/events?actorId=user-123&page=0&size=20"
```

### 3. Redact Audit Event Payload
Perform structured redaction on specific JSON pointers within a payload. The original content-hash commitment is preserved.
```bash
curl -X POST http://localhost:8080/audit/events/{id}/redact \
  -H "Content-Type: application/json" \
  -d '{
    "paths": ["/ip"]
  }'
```

### 4. Archive Old Records (Retention)
Soft-archive all active records strictly older than the specified cutoff timestamp.
```bash
curl -X POST "http://localhost:8080/audit/retention/archive?before=2025-01-01T00:00:00Z"
```

### 5. Bulk Export Audit Events
Export a self-contained, offline-verifiable JSON bundle for a specific resource or actor.
```bash
curl -X GET "http://localhost:8080/audit/export?resourceId=auth-server"
```

### 6. Verify Global Chain Integrity
Trigger an exhaustive cryptographic verification of the entire database hash-chain.
```bash
curl -X GET http://localhost:8080/audit/verify
```

## Scenario Summaries

### Scenario A: Core Audit Ledger
Implemented a strictly append-only audit ledger where each event is cryptographically anchored to the previous event forming a linear hash-chain. We use deterministic SHA-256 content hashing (canonicalizing JSON payloads) to guarantee data integrity. The `GET /audit/verify` endpoint dynamically recalculates hashes across the entire database to detect post-write tampering. Update and delete API operations are strictly prohibited.

### Scenario B: Data Lifecycle (Retention, Redaction, Export)
- **Retention**: Records are soft-archived rather than physically deleted to maintain continuous chain integrity.
- **Structured Redaction**: Granular JSON node redaction replaces targeted data with `{"redacted": true}`. The original `contentHash` is retained as a mathematical commitment.
- **Bulk Export**: Regulators can export a subset of records. The export logically threads the global chain and provides boundary metadata (`firstExportedRecordPreviousHash`) allowing independent cryptographic verification of the sparse subset.

### Scenario C: Regulatory Compliance Audit
Analyzed the ambiguous requirement: *"Regulators need to be able to audit access to client account data."* We normalized this by mapping read/write accesses to existing event properties (`eventType=ACCOUNT_READ`, `resourceType=CLIENT_ACCOUNT`). This approach fully satisfied the regulatory requirement natively using the existing query and export APIs without polluting the generic architecture with domain-specific endpoints.

## Tamper-Verification Demonstration

You can locally demonstrate the system's ability to detect unauthorized database tampering:

1. **Start the application** (`mvn spring-boot:run`).
2. **Create an event**: Use the Create Audit Event `curl` command above. Note the generated ID.
3. **Verify Intact Chain**: Run `curl -X GET http://localhost:8080/audit/verify`. You will see `"valid": true` and `"message": "Audit chain is intact"`.
4. **Tamper via SQL**: Connect to your local MySQL database and modify the payload directly:
   ```sql
   UPDATE audit_records SET payload = '{"ip": "9.9.9.9"}' WHERE actor_id = 'user-123';
   ```
5. **Detect Tampering**: Run `curl -X GET http://localhost:8080/audit/verify` again.
6. **Expected Result**: The system will return a `200 OK` response with `"valid": false` and `"violationType": "CONTENT_HASH_MISMATCH"`. This mathematically proves the post-write database manipulation was caught.

## Known Limitations / Prototype vs. Production

This prototype strictly addresses the core cryptographic mechanisms. In a production environment, the following limitations must be addressed:
* **Memory Pressure**: The export and verification services currently load the entire chain into memory (`findAll()`) to build a topological map. For very large datasets, this will cause Out-Of-Memory (OOM) errors. Production would require streaming or Recursive CTEs.
* **Security & IAM**: Authentication and authorization are intentionally out of scope. A production deployment requires an API Gateway or Spring Security integration.
* **Completeness Trust Boundary**: The audit ledger cryptographically guarantees the integrity of events *it receives*. However, if an upstream system has a bug and fails to emit an event, the ledger will be blind to it. We cannot mathematically guarantee global real-world completeness.
* **Truncation/Rewrite**: An internal hash-chain ensures internal consistency. However, a malicious DBA could delete the tail of the chain entirely. Preventing tail-truncation requires periodically anchoring the `globalChainTipHash` to an external trusted immutable ledger (which is out of scope here).
* **Configuration**: Prototype database credentials (e.g., default `root`) must be externalized to a secure vault for production.
* **Redaction Re-hashing**: While redacted records preserve the original `contentHash` commitment, the original plaintext payload is permanently overwritten. Independent offline auditors cannot fully re-verify the hash of redacted records without out-of-band access to the original plaintext.
