# Audit Log Service Architecture

## 1. Overview
The Audit Log Service is a robust, append-only cryptographic ledger prototype designed to enforce immutability and tamper-evidence for sensitive enterprise operations. It provides generic ingestion, filtering, granular redaction, retention management, and bulk export capabilities while mathematically guaranteeing data integrity.

## 2. Layered Architecture
The application follows a standard Spring Boot layered architecture:
- **Controller Layer**: Exposes REST endpoints (`AuditController`, `RedactionController`, `RetentionController`, `ExportController`, `VerificationController`), maps HTTP requests to DTOs, and centralizes validation via `GlobalExceptionHandler`.
- **Service Layer**: Orchestrates business logic, cryptographic hashing (`HashService`), verification algorithms (`ChainVerificationService`), and transactional boundaries.
- **Repository Layer**: Utilizes Spring Data JPA and Hibernate to abstract MySQL database operations, including custom JPQL and specification-based querying.
- **Data Layer**: A local MySQL 8 database leveraging unique constraints to enforce structural chain integrity.

## 3. Main Components
- **AuditService**: Handles ingestion of new events, optimistic concurrency retries, and paginated querying.
- **HashService**: Responsible for canonicalizing JSON payloads and computing deterministic SHA-256 content and record hashes.
- **ChainVerificationService**: Iterates over the persisted ledger to recalculate hashes and structurally detect forks, cycles, and tampering.
- **RedactionService**: Safely modifies specific JSON pointers within a payload while preserving the original cryptographic commitment.
- **RetentionService**: Performs bulk soft-archival updates to enforce lifecycle policies without deleting rows.
- **ExportService**: Reconstructs sparse sub-chains and prepares offline-verifiable metadata bundles.

## 4. AuditRecord Data Model
The central entity is `AuditRecord`, persisted to the `audit_records` table.
Key fields include:
- `id`: UUID primary key.
- `eventType`, `actorId`, `resourceType`, `resourceId`: Indexed strings for flexible categorization and filtering.
- `payload`: A JSON column (`@JdbcTypeCode(SqlTypes.JSON)`) storing arbitrary contextual data.
- `timestamp`: Event occurrence time.
- `previousHash`: (Unique, Length 64) Anchor to the preceding record, structurally enforcing a linear chain.
- `contentHash`: (Length 64) The deterministic SHA-256 hash of the record's raw properties.
- `recordHash`: (Length 64) The SHA-256 hash combining `contentHash` and `previousHash`.
- `status`: Enum (`ACTIVE`, `ARCHIVED`, `REDACTED`) managing lifecycle states.

## 5. API / Service / Repository Responsibilities
- **APIs** strictly handle HTTP parsing, DTO validation (via `jakarta.validation`), and JSON serialization.
- **Services** compute hashes, traverse chains, and apply atomic business rules (e.g., verifying a record is not already redacted before modifying).
- **Repositories** strictly enforce database constraints (e.g., `UNIQUE(previous_hash)`) and abstract complex queries like finding the chain tip (`findCurrentChainHead()`).

## 6. Hashing Algorithm
The system exclusively uses the **SHA-256** cryptographic hash algorithm. It is highly collision-resistant and standard for compliance ledgers.

## 7. Deterministic/Canonical Hashing Approach
Because JSON does not guarantee key ordering natively, computing a hash directly from a serialized JSON string is fragile. `HashService` dynamically canonicalizes the `payload`:
- JSON Object keys are recursively sorted alphabetically using a `TreeMap`.
- JSON Array item ordering is strictly preserved.
- Database-generated/mutable fields (`id`, `createdAt`, `status`) are intentionally excluded from the content hash calculation.
- The canonical representation is then hashed to produce the `contentHash`.

## 8. Hash-Chain Construction
The ledger is structured as a singly linked list.
Each new record calculates its `contentHash`, fetches the `recordHash` of the absolute latest entry in the database, sets it as its `previousHash`, and then hashes `contentHash + "|" + previousHash` to derive its own `recordHash`.

## 9. Genesis Value
The very first record in the database has no predecessor. Its `previousHash` is explicitly set to the string `"GENESIS"`. The `ChainVerificationService` actively validates that exactly one `"GENESIS"` record exists.

## 10. Chain Verification
`GET /audit/verify` executes an exhaustive integrity check:
1. **Content Integrity**: Recalculates the canonical SHA-256 hash for every `ACTIVE` and `ARCHIVED` record to detect bit-rot or tampering (`CONTENT_HASH_MISMATCH`).
2. **Linkage Integrity**: Recalculates `recordHash` to ensure the mathematical coupling to the predecessor remains unbroken.
3. **Structural Integrity**: Maps the entire chain in memory to ensure there are no forks, isolated cycles, or disconnected orphans.

## 11. Retention Behavior
Records are **Soft Archived** rather than deleted. `RetentionService` executes a native JPQL update to change the `status` of old records to `ARCHIVED`. Because `status` is excluded from the `contentHash`, the cryptographic chain remains 100% intact, satisfying both compliance retention limits and cryptographic unbroken-chain requirements.

## 12. Redaction Scheme and Tradeoffs
Privacy mandates (e.g., GDPR/CCPA) necessitate removing PII. `RedactionService` uses JSON Pointers to surgically replace specific payload nodes with `{"redacted": true}`, updating the status to `REDACTED`.
**Tradeoff**: The original `contentHash` is preserved as a permanent commitment, but because the plaintext PII is destroyed, independent auditors cannot natively recalculate the `contentHash` of a redacted record unless the plaintext was secured in an external out-of-band vault.

## 13. Bulk Export and Independent Verification
`GET /audit/export` extracts a filtered subset of records (e.g., all events for `actorId=X`).
The export logically threads the global chain, retrieving the exact matching records in perfect topological order. The bundle includes crucial boundary metadata (`firstExportedRecordPreviousHash`, `firstExportedRecordHash`, `globalChainTipHash`). This permits external auditors to independently recalculate the structural linkage of the sparse export without needing the entire multi-terabyte database.

## 14. Concurrency / Append Behavior
High-throughput ingestion is managed via **Optimistic Concurrency Control (OCC)**. 
MySQL strictly enforces a unique constraint on `previous_hash`. If two threads concurrently attempt to append to the same chain tip, one will succeed and the other will trigger a `DataIntegrityViolationException`. `AuditService` gracefully catches this and automatically retries the operation, dynamically fetching the new tip and re-syncing the append order safely.

## 15. Security and Production-Readiness Considerations
- **Immutability Limits**: The internal hash chain guarantees tamper-evidence. However, it cannot prevent a rogue DBA from truncating the end of the table. Production readiness requires periodically anchoring the `globalChainTipHash` to an external trusted entity (e.g., a public blockchain, AWS QLDB, or a daily published receipt).
- **Error Handling**: A centralized `GlobalExceptionHandler` masks internal stack traces while providing predictable, typed JSON errors for validation faults.

## 16. Known Limitations
- **Unbounded Memory Loading**: `ChainVerificationService` and `ExportService` currently utilize `findAll()` to build topological graph maps in memory. While acceptable for a prototype, production databases with millions of rows will crash due to Out-Of-Memory (OOM) errors. Future scaling requires recursive CTEs or bounded stream processing.
- **Authentication (IAM)**: Excluded by prototype scope. Production requires an API Gateway and JWT validation.
- **Completeness Guarantees**: The service mathematically proves the integrity of events it *receives*, but cannot detect if an upstream application crashed or silently failed to report an access event.

## 17. Security Layer

The application implements a stateless API security model dictated by Spring profiles to strictly separate developer experience from production posture.

### Profile-Based Security Splits
1. **DEV Profile (DevSecurityConfig)**: Exposes HTTP Basic Authentication. Credentials are configurable via environment variables (DEV_USER / DEV_PASSWORD) to avoid exposing hardcoded credentials in the repository while keeping local testing simple.
2. **PROD Profile (ProdSecurityConfig)**: Acts as an OAuth2 Resource Server. It enforces stateless JWT validation. Note that Spring Security performs issuer/JWK discovery during application initialization, requiring outbound network connectivity to the IDP at startup. Once the keys are cached, per-request signature validation is mathematically offline. The OIDC issuer and JWK URIs are externalized (OIDC_ISSUER_URI), ensuring no hardcoded keys or vendor-specific integrations exist in the source code. It additionally implements explicit audience validation via the AudienceValidator.

### CORS Strategy
CORS is profile-specific.
- The dev profile allows localhost/dev URLs by default.
- The prod profile does not permit wildcard (*) origins. Allowed origins must be explicitly injected via the PROD_ALLOWED_ORIGINS environment variable, and * is strictly prohibited by configuration code at initialization.

### Rate Limiting Architecture
To satisfy the constraint against bringing in heavy infrastructure (like Redis), we implemented a lightweight, in-memory **Token Bucket algorithm using Bucket4j** within a Servlet Filter (RateLimitFilter).
- **Identifier**: It scopes rate limits to the authenticated principal. If unauthenticated, it falls back to the client IP.
- **Limitation Tradeoff**: Because it relies on ConcurrentHashMap and local JVM state, it is strictly a per-instance limiter.