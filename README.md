# Audit Log Service



A lightweight, cryptographically verifiable, append-only audit ledger built with Spring Boot.



This project implements a compliance-grade audit logging Audit Log Service designed for security and regulatory environments. It utilizes a continuous cryptographic hash-chain (similar to a cryptographic hash chain) to mathematically guarantee the integrity of all logged events and definitively detect unauthorized tampering.



## Setup Instructions



**Prerequisites:**

- Java 21+

- Maven 3.9+

- MySQL 8.0+



1. Create a MySQL database named udit_db.

   `sql

   CREATE DATABASE audit_db;

   `

2. Set your environment variables (or rely on the defaults in pplication.yml):

   `

   SPRING_DATASOURCE_URL=jdbc:mysql://localhost:3306/audit_db

   SPRING_DATASOURCE_USERNAME=root

   SPRING_DATASOURCE_PASSWORD=yourpassword

   `

3. Run the application:

   `ash

   mvn spring-boot:run

   `

4. Access the Swagger UI for API exploration and interactive testing:

   http://localhost:8080/swagger-ui/index.html



### How to test using Swagger UI



1. Open the Swagger UI link in your browser.

2. Click the **Authorize** button (the padlock icon at the top right).

3. The application is configured to run in the dev profile by default. Enter the default credentials:

   - **Username**: dmin

   - **Password**: dmin

4. Click **Authorize** and then **Close**.

5. You can now expand any endpoint (e.g., POST /audit/events), click **Try it out**, fill in the request body, and click **Execute**.



**Important for Production (prod profile) Testing:**

If you run the application with --spring.profiles.active=prod, Basic Auth is disabled. You must obtain a valid JWT from your configured OIDC Issuer, click the **Authorize** button in Swagger, and provide the JWT token (e.g., Bearer eyJhbG...).



## Security & Profiles



This application requires security to access the APIs. The security implementation is profile-driven:



### Development Profile (--spring.profiles.active=dev)

- **Security Strategy**: HTTP Basic Authentication

- **Credentials**: Uses environment variables ${DEV_USER} and ${DEV_PASSWORD} (defaults to admin/admin if unset).

- **Authorization**: The default user is automatically assigned all required scopes/roles.

- **CORS**: Allows requests from ${DEV_ALLOWED_ORIGINS} (defaults to http://localhost:3000,http://localhost:8080).

- **Rate Limiting**: 100 requests per minute per authenticated principal/IP.



### Production Profile (--spring.profiles.active=prod)

- **Security Strategy**: JWT / OAuth2 Resource Server (No Basic Auth).

- **OIDC Configuration**: You must set ${OIDC_ISSUER_URI} and ${OIDC_AUDIENCE} in your environment. Spring Security performs issuer/JWK discovery during application initialization. The application therefore requires connectivity to the configured OIDC issuer/JWK discovery endpoint when initializing the JWT decoder. Once the signing keys are available/cached, individual JWT signature validation does not require a network call for every request. A fully air-gapped environment would require a different key-management/configuration approach and is outside this prototype's scope.

- **Authorization**: Token must include explicitly mapped OAuth scopes (e.g. SCOPE_audit:read, SCOPE_audit:write, SCOPE_audit:redact, SCOPE_audit:archive, SCOPE_audit:export, SCOPE_audit:verify).

- **CORS**: STRICTLY requires ${PROD_ALLOWED_ORIGINS} environment variable. Unrestricted * is not supported.

- **Rate Limiting**: 1000 requests per minute.



> [!WARNING]

> The rate limiter (Bucket4j) is strictly in-memory and per-instance. It is not distributed across a cluster.



## Testing & Code Coverage



This project uses **JaCoCo** to track test coverage across the application. 



To execute the entire test suite (Unit, Integration, and Security tests) and generate the coverage report, run the final quality gate:



`ash

mvn clean verify

`



**Final Test Results (Quality Gate):**

- **Total Tests Run**: 79

- **Failures**: 0

- **Errors**: 0

- **Skipped**: 0



**Coverage Metrics:**

- **Instruction Coverage**: 86%

- **Branch Coverage**: 67%



## Testing & Security Evidence

- Command executed: mvn clean verify
- Total tests: 82
- Failures: 0
- JaCoCo Instruction Coverage: 87%
- Security-critical authorization and verification paths have focused automated coverage.
- Authentication tests verify 401s on unauthenticated access.
- Authorization tests verify 403s on bypass attempts.
- Redaction tampering tests prove forged DBA overrides are rejected.
- Chain tampering tests capture payload, record, and structural modifications.





**How to view the JaCoCo coverage report:**

1. After the Maven command completes successfully, navigate to the newly generated 	arget directory.

2. Open the file located at: 	arget/site/jacoco/index.html

3. You can simply double-click the index.html file to open it in your web browser (Chrome, Edge, Firefox, etc.).

4. The web dashboard will provide a comprehensive breakdown of Instruction, Branch, and Line coverage per package and class.



## API Overview



### 1. Create Audit Event

Record a new event into the append-only ledger. Requires SCOPE_audit:write.

`ash

curl -X POST http://localhost:8080/audit/events \

  -H "Content-Type: application/json" \

  -u admin:admin \

  -d '{

    "eventType": "LOGIN_SUCCESS",

    "actorId": "user-123",

    "resourceType": "SYSTEM",

    "resourceId": "auth-server",

    "payload": {"ip": "192.168.1.50"}

  }'

`



### 2. Query Audit Events

Retrieve audit events with optional filtering and pagination. Requires SCOPE_audit:read.

`ash

curl -X GET "http://localhost:8080/audit/events?actorId=user-123&page=0&size=20" -u admin:admin

`



### 3. Redact Audit Event Payload

Perform structured redaction on specific JSON pointers within a payload. The original content-hash commitment is preserved. Requires SCOPE_audit:redact.

`ash

curl -X POST http://localhost:8080/audit/events/{id}/redact \

  -H "Content-Type: application/json" \

  -u admin:admin \

  -d '{

    "paths": ["/ip"]

  }'

`



### 4. Archive Old Records (Retention)

Soft-archive all active records strictly older than the specified cutoff timestamp. Requires SCOPE_audit:archive.

`ash

curl -X POST "http://localhost:8080/audit/retention/archive?before=2025-01-01T00:00:00Z" -u admin:admin

`



### 5. Bulk Export Audit Events

Export a self-contained, offline-verifiable JSON bundle for a specific resource or actor. Requires SCOPE_audit:export.

`ash

curl -X GET "http://localhost:8080/audit/export?resourceId=auth-server" -u admin:admin

`



### 6. Verify Global Chain Integrity

Trigger an exhaustive cryptographic verification of the entire database hash-chain. Requires SCOPE_audit:verify.

`ash

curl -X GET http://localhost:8080/audit/verify -u admin:admin

`



## Scenario Summaries



### Scenario A: Core Audit Ledger

Implemented a strictly append-only audit ledger where each event is cryptographically anchored to the previous event forming a linear hash-chain. We use deterministic SHA-256 content hashing (canonicalizing JSON payloads) to guarantee data integrity. The GET /audit/verify endpoint dynamically recalculates hashes across the entire database to detect post-write tampering. Update and delete API operations are strictly prohibited.



### Scenario B: Data Lifecycle (Retention, Redaction, Export)

- **Retention**: Records are soft-archived rather than physically deleted to maintain continuous chain integrity.

- **Structured Redaction**: Granular JSON node redaction replaces targeted data with {"redacted": true}. The original contentHash is retained as a mathematical commitment.

- **Bulk Export**: Regulators can export a subset of records. The export logically threads the global chain and provides boundary metadata (irstExportedRecordPreviousHash) allowing independent cryptographic verification of the sparse subset.



### Scenario C: Regulatory Compliance Audit

Analyzed the ambiguous requirement: *"Regulators need to be able to audit access to client account data."* We normalized this by mapping read/write accesses to existing event properties (eventType=ACCOUNT_READ, 

esourceType=CLIENT_ACCOUNT). This approach fully satisfied the regulatory requirement natively using the existing query and export APIs without polluting the generic architecture with domain-specific endpoints.



## Proactive Hardening & Adversarial Defense



To ensure true non-repudiation and structural resilience against sophisticated internal threats (e.g. compromised DBA accounts), several defense-in-depth measures have been introduced:



1. **Authorization Hardening**: Authentication alone is no longer enough to perform sensitive operations. Access to endpoints is secured by fine-grained permissions mapping to operations (SCOPE_audit:read, SCOPE_audit:verify, SCOPE_audit:redact, etc.), preventing privilege escalation via standard JWTs lacking regulatory scopes.

2. **Redaction Cryptographic Invariants**: A vulnerability previously existed where a DBA could update an event payload to hide malicious activity, change the database row status to REDACTED, and bypass verification. A new cryptographic commitment, 

edactionDigest, was implemented. It binds the original contentHash to the *redacted* payload mathematically during the application-layer API workflow, ensuring verifiers will catch and reject naive SQL-level REDACTED status overrides.



## Tamper-Verification Demonstration



You can locally demonstrate the system's ability to detect unauthorized database tampering.



1. **Start the application** (mvn spring-boot:run).

2. **Create an event**: Use the Create Audit Event curl command above. Note the generated ID.

3. **Verify Intact Chain**: Run curl -X GET http://localhost:8080/audit/verify -u admin:admin. You will see "valid": true and "message": "Audit chain is intact".



Now, connect to your local MySQL database and run these safe demonstrations (one by one, restoring after each, or observe the failure):



**A. Payload Tampering**

`sql

UPDATE audit_records SET payload = '{"ip": "9.9.9.9"}' WHERE actor_id = 'user-123';

`

*Expected Violation*: CONTENT_HASH_MISMATCH - The payload no longer matches the contentHash.



**B. RecordHash Tampering**

`sql

UPDATE audit_records SET record_hash = 'tampered' WHERE actor_id = 'user-123';

`

*Expected Violation*: RECORD_HASH_MISMATCH - The structural hash combining the content and previous hash is corrupted.



**C. PreviousHash Tampering (Breaking the Chain)**

`sql

UPDATE audit_records SET previous_hash = 'broken' WHERE actor_id = 'user-123';

`

*Expected Violation*: BROKEN_LINKAGE or MULTIPLE_GENESIS - The topological graph can no longer connect this record to the rest of the chain.



**D. Forged REDACTED Status Without Digest**

`sql

UPDATE audit_records SET status = 'REDACTED', payload = '{"redacted": true}' WHERE actor_id = 'user-123';

`

*Expected Violation*: REDACTION_METADATA_MISMATCH - The verifier expects a mathematical proof binding the original payload hash to this redaction, but none exists.



**E. Invalid RedactionDigest**

`sql

UPDATE audit_records SET status = 'REDACTED', payload = '{"redacted": true}', redaction_digest = 'forged123' WHERE actor_id = 'user-123';

`

*Expected Violation*: REDACTION_METADATA_MISMATCH - The provided digest does not match the computed SHA-256(originalContentHash + "|REDACTED|" + payloadString).





## Known Limitations / Prototype vs. Production



This prototype strictly addresses the core cryptographic mechanisms. In a production environment, the following limitations must be addressed:

* **Memory Pressure**: The export and verification services currently load the entire chain into memory (indAll()) to build a topological map. For very large datasets, this will cause Out-Of-Memory (OOM) errors. Production would require streaming or Recursive CTEs.

* **Completeness Trust Boundary**: The audit ledger cryptographically guarantees the integrity of events *it receives*. However, if an upstream system has a bug and fails to emit an event, the ledger will be blind to it. We cannot mathematically guarantee global real-world completeness.

* **Truncation/Rewrite**: An internal hash-chain ensures internal consistency. However, a malicious DBA could delete the tail of the chain entirely. Preventing tail-truncation requires periodically anchoring the globalChainTipHash to an external trusted immutable ledger (which is out of scope here).

* **Configuration**: Prototype database credentials (e.g., default 

oot) must be externalized to a secure vault for production.
