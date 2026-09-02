# AI Usage Log

This document tracks all AI-assisted interactions, architectural contributions, code generation, and test development activities for the **AI-Assisted Software Engineering System — Audit Log Service** project.

---

## Log Entry 1: Project Scaffolding & Foundation Setup

- **Timestamp**: 2026-09-01
- **Activity**: Project Foundation & Requirements Specification
- **AI Tool / System**: Antigravity (Google DeepMind)
- **Scope & Objectives**:
  - Initialized Maven build configuration (`pom.xml`) with Java 21, Spring Boot 3.3.3, Spring Web, Validation, Lombok, Springdoc OpenAPI, and Spring Boot Test.
  - Established a clean layered package structure:
    - `com.example.auditlog.controller`
    - `com.example.auditlog.service`
    - `com.example.auditlog.repository`
    - `com.example.auditlog.entity`
    - `com.example.auditlog.dto`
    - `com.example.auditlog.exception`
    - `com.example.auditlog.config`
    - `com.example.auditlog.util`
  - Created root Spring Boot Application entry point (`AuditLogApplication.java`).
  - Documented client requirements across all 12 key dimensions in `docs/requirements.md`.
  - Created developer `README.md` and project `ATTESTATION.md`.

---

## Log Entry 2: Local MySQL 8 Database Configuration & Connection Verification

- **Timestamp**: 2026-09-02
- **Activity**: Local MySQL 8 Integration & Dynamic Environment Configuration
- **AI Tool / System**: Antigravity (Google DeepMind)
- **Scope & Objectives**:
  - Configured Spring Data JPA, Hibernate ORM, and MySQL Connector/J for local MySQL 8 database (`auditdb` on `localhost:3306`).
  - Implemented dynamic database configuration in `application.yml` via environment variables (`DB_USERNAME`, `DB_PASSWORD`, `DB_HOST`, `DB_PORT`, `DB_NAME`) with zero hardcoded credentials.
  - Configured UTC timezone handling across JDBC driver parameters and Hibernate session context.
  - Added automated integration test in `AuditLogApplicationTests.java` asserting `DataSource` injection and live connection validation via `Connection.isValid(2)`.
  - Documented local environment variable setup for PowerShell, CMD, and Bash in `README.md`.
- **Human Oversight & Verification**:
  - Maintained architectural boundaries: no business logic, domain entities, or REST endpoints created prematurely.
  - Verified successful connection and test execution via `mvn clean test` against local MySQL 8 instance.

---

## Log Entry 3: Core Persistence Model (Commit #3)

- **Timestamp**: 2026-09-02
- **Activity**: Persistence Entity & Repository Implementation
- **AI Tool / System**: Antigravity (Google DeepMind)
- **Scope & Objectives**:
  - Created the core `AuditRecord` JPA entity with a UUID primary key, `AuditRecordStatus` enum, and metadata fields (`previousHash`, `recordHash`, `createdAt`).
  - Leveraged Hibernate 6 `@JdbcTypeCode(SqlTypes.JSON)` to map Jackson's `JsonNode` directly to a MySQL 8 native JSON column for the event payload.
  - Created `AuditRecordRepository` interface extending `JpaRepository`.
  - Added DB persistence integration tests leveraging `@AutoConfigureTestDatabase(replace = Replace.NONE)`.

---

## Log Entry 4: Write API Implementation (Commit #4)

- **Timestamp**: 2026-09-02
- **Activity**: POST `/audit/events` API, Validation, & Service Logic
- **AI Tool / System**: Antigravity (Google DeepMind)
- **Scope & Objectives**:
  - Implemented `AuditEventRequest` and `AuditEventResponse` DTOs to cleanly separate API boundaries from internal DB fields.
  - Integrated Jakarta Bean Validation (`@NotBlank`, `@NotNull`, `@Size`) at the controller boundary.
  - Engineered `AuditService` layer to coordinate business logic, including server-assigned timestamping via `Instant.now()` fallback.
  - Configured transaction synchronization utilizing `saveAndFlush()` to instantly populate `@CreationTimestamp` properties for API responses.
  - Developed comprehensive `MockMvc` integration tests validating HTTP 201 creation, 400 rejection, and exact timestamp preservation.

---

## Log Entry 5: Read API Implementation with Filtering & Pagination (Commit #5)

- **Timestamp**: 2026-09-02
- **Activity**: GET `/audit/events` API with JPA Specifications
- **AI Tool / System**: Antigravity (Google DeepMind)
- **Scope & Objectives**:
  - Engineered `PagedResponse` DTO to standardize output structures (`content`, `totalElements`, `totalPages`).
  - Leveraged Spring Data JPA `Specification` API (`AuditRecordSpecification`) for highly dynamic, safe, and optional SQL query filtering (`actorId`, `resourceType`, `eventType`, `from`, `to`).
  - Enforced pairwise constraint rules (e.g., `resourceType` & `resourceId` must be provided together).
  - Implemented standard pagination and deterministic fallback ordering (sorting by `timestamp` ASC, then `id` ASC).
  - Wrote 12 new comprehensive `MockMvc` integration tests thoroughly validating combinations, boundaries, pagination sizes, and missing parameters.

---

## Log Entry 6: Deterministic SHA-256 Hashing Component (Commit #6)

- **Timestamp**: 2026-09-02
- **Activity**: Hashing Service & JSON Canonicalization Logic
- **AI Tool / System**: Antigravity (Google DeepMind)
- **Scope & Objectives**:
  - Designed the `HashService` component to exclusively map immutable event properties while safely ignoring DB-generated metrics (`id`, `createdAt`, `status`).
  - Implemented deep canonicalization processing for the unstructured `payload` using recursive `JsonNode` inspection and `TreeMap` structures, enforcing strictly alphabetical JSON property evaluation regardless of initial key ordering.
  - Implemented native `MessageDigest` SHA-256 processing to yield standardized 64-character lowercase hex strings.
  - Documented the hashing architectural design in `docs/hashing.md`.
  - Added 11 unit tests aggressively verifying hash collisions, mutation detection, and deterministic outputs on heavily jumbled JSON payloads.

---

## Log Entry 7: Hashing Component Refinements (Commit #6 Updates)

- **Timestamp**: 2026-09-02
- **Activity**: Dependency Injection & Array Ordering Tests
- **AI Tool / System**: Antigravity (Google DeepMind)
- **Scope & Objectives**:
  - Refactored `HashService` to use standard Spring dependency injection (`@RequiredArgsConstructor`) for the `ObjectMapper` bean, rather than manually instantiating it, ensuring context consistency.
  - Expanded unit testing to prove that JSON arrays are treated distinctively from objects during canonicalization. A specific test was added validating that altering the order of elements inside a JSON array intentionally alters the SHA-256 hash (as array sequences are semantically meaningful).
  - Updated `docs/hashing.md` to explicitly state the handling rules for JSON arrays compared to standard JSON object sorting.

---

## Log Entry 8: Tamper-Evident Hash Chaining (Commit #7)

- **Timestamp**: 2026-09-02
- **Activity**: Cryptographic Hash Chaining & Concurrency Safeguards
- **AI Tool / System**: Antigravity (Google DeepMind)
- **Scope & Objectives**:
  - Applied a `UNIQUE` index to the `previous_hash` column within the database schema to physically prevent chain forking and mathematically enforce linear history constraints.
  - Implemented `calculateRecordHash()` to tightly couple the immutable `contentHash` with the `previousHash`.
  - Adopted an "Optimistic Concurrency Control" mechanism that traps Spring's `DataIntegrityViolationException`, allowing concurrent threads to automatically retry and re-sync their append order safely under load.
  - Switched from timestamp-based chain ordering to strict "Topological Append-Order" using an exact database relationship query `NOT EXISTS (SELECT 1 FROM AuditRecord b WHERE b.previousHash = a.recordHash)`.
  - Added severe multi-threaded barrage testing `HashChainIntegrationTest` proving deterministic chaining despite event timestamp overlaps.
  - Created structural documentation detailing the system design in `docs/chaining.md`.

---

## Log Entry 9: Hash Chain Verification API (Commit #8)

- **Timestamp**: 2026-09-02
- **Activity**: GET `/audit/verify` API Implementation & Database Tampering Proofs
- **AI Tool / System**: Antigravity (Google DeepMind)
- **Scope & Objectives**:
  - Implemented a complete cryptographic chain verifier `ChainVerificationService` executing via `GET /audit/verify`.
  - Constructed the traversal algorithm mapped in `Map<String, List<AuditRecord>>` to detect cycle relationships, orphans (`DISCONNECTED_RECORD`), forks, broken linkages, and origin violations (`MISSING_GENESIS` / `MULTIPLE_GENESIS`).
  - Added automatic recalculation matching on all events to flag altered fields returning `RECORD_HASH_MISMATCH`.
  - Defined explicit DTO structures (`VerificationResponse`) isolating diagnostic outputs from standard queries.
  - Used Spring JDBC Template in `VerificationIntegrationTest` to forcibly simulate raw database breaches (bypassing Hibernate cache mappings) specifically to prove the verifier successfully flags unauthorized modifications natively stored in MySQL.
  - Wrote explicit limitation reporting in `docs/verification.md`.

---

## Log Entry 10: Scenario A Completion & End-to-End Validation (Commit #9)

- **Timestamp**: 2026-09-02
- **Activity**: Finalizing Scenario A, Append-Only Checks, & E2E Testing
- **AI Tool / System**: Antigravity (Google DeepMind)
- **Scope & Objectives**:
  - Executed a comprehensive assessment of the Commits #1-#8 integration.
  - Discovered and resolved a subtle MySQL precision truncation bug natively truncating Java's `Instant.now()` (nanoseconds) to MySQL's `TIMESTAMP(6)` (microseconds). Fixed by enforcing `.truncatedTo(ChronoUnit.MILLIS)` in the assignment logic to ensure symmetric hash recalculation upon DB read.
  - Fortified the API's strict append-only constraints by generating and testing `MockMvc` configurations explicitly asserting HTTP `404 Not Found` or `405 Method Not Allowed` for `PUT`, `PATCH`, and `DELETE` events.
  - Designed `ScenarioAEndToEndTest.java`, an interview-friendly integration flow successfully navigating event creation, querying, successful verification, simulating a malicious database-layer UPDATE via JDBC, and successfully returning `valid = false`.
  - Composed the final project summary document `docs/scenario-a.md` detailing the implemented functionalities and identified constraints before concluding the milestone.

---

## Log Entry 11: Audit Log Retention / Soft Archival (Commit #10)

- **Timestamp**: 2026-09-02
- **Activity**: Implementing Scenario B (Retention) with Soft Archival
- **AI Tool / System**: Antigravity (Google DeepMind)
- **Scope & Objectives**:
  - Engineered a **Soft Archival** mechanism (RetentionService) to transition records older than a specified cutoff timestamp from ACTIVE to ARCHIVED status.
  - Utilized a highly efficient native JPA @Modifying bulk update query (archiveOldRecords) to perform archival idempotently without loading entities into memory.
  - Preserved complete cryptographic chain integrity by ensuring status changes do not affect contentHash, previousHash, or recordHash fields.
  - Exposed a strict internal-facing API endpoint (POST /audit/retention/archive?before=<timestamp>) explicitly preventing individual arbitrary record modifications.
  - Developed comprehensive integration tests (RetentionIntegrationTest) mathematically asserting that all core cryptographic properties, hashes, and payload contents remain identical bit-for-bit before and after the archival transition.
  - Drafted docs/retention.md documenting the design decisions, explaining why physical deletion fundamentally compromises hash-chain integrity, and outlining the tradeoffs of client-supplied timestamps vs. ingestion-time logic.

---

## Log Entry 12: Structured Redaction (Commit #11)

- **Timestamp**: 2026-09-02
- **Activity**: Implementing Scenario B (Structured Redaction)
- **AI Tool / System**: Antigravity (Google DeepMind)
- **Scope & Objectives**:
  - Implemented `contentHash` column explicitly persisting the original content cryptographic commitment.
  - Built `RedactionService` executing atomic JSON Pointer node replacements (`{"redacted": true}`) over complex objects/arrays while perfectly maintaining surrounding payloads.
  - Implemented hard fail-fast validation against invalid JSON pointers and missing paths ensuring transactional atomicity (`HTTP 400 Bad Request`).
  - Adapted `ChainVerificationService` distinguishing between `ACTIVE` and `REDACTED` records, ensuring redacted structures bypass full hash recalculation while proving mathematically they remain legally anchored to their original hashes.
  - Composed `RedactionIntegrationTest` extensively covering deep array modifications, syntax checks, multiple-field operations, and explicit API testing.
  - Authored `docs/redaction.md` explicitly identifying the privacy tradeoff (unredacted payloads are fundamentally stripped and must be secured out-of-band for legal re-verifications).

---

## Log Entry 13: Bulk Export (Scenario B)

- **Timestamp**: 2026-09-02
- **Activity**: Implementing Scenario B (Bulk Export)
- **AI Tool / System**: Antigravity (Google DeepMind)
- **Scope & Objectives**:
  - Implemented `ExportService` and `GET /audit/export` endpoint yielding self-contained, mathematically verifiable JSON bundles.
  - Defined `ExportBundle`, `ExportMetadata`, and `ExportRecord` DTOs enforcing cryptographic boundaries (`firstExportedRecordHash`, `globalChainTipHash`).
  - Achieved rigorous topological sorting of filtered subsets by mapping the global chain via `previousHash` links.
  - Integrated offline verification logic proving `contentHash` and `recordHash` re-calculations natively support omitted boundaries.
  - Created robust integration tests covering API layer validation, filtering correctly, and programmatic cryptographic assertion over `ARCHIVED` and `REDACTED` payloads inside the exported bundle.
  - Documented explicit mathematical limitations detailing why sparse linear hash-chains guarantee tamper-evidence but not completeness in `docs/export.md`.
---

## Log Entry 14: Regulator Access Audit (Scenario C)

- **Timestamp**: 2026-09-02
- **Activity**: Implementing Scenario C (Access Audit Documentation & E2E Test)
- **AI Tool / System**: Antigravity (Google DeepMind)
- **Scope & Objectives**:
  - Analyzed and documented the highly ambiguous regulatory requirement for tracking access to client account data in `docs/scenario-c.md`.
  - Maintained the strict zero-architectural-change constraint by validating that the existing generic event properties (`eventType=ACCOUNT_READ`, `resourceType=CLIENT_ACCOUNT`) natively fulfilled the core ACs.
  - Formally differentiated between **tamper-evidence** (proving cryptographic integrity of received data) and **completeness limits** (trust boundaries failing to emit data) in the documentation.
  - Orchestrated `ScenarioCEndToEndTest.java` leveraging MockMvc to simulate the entire regulatory audit lifecycle: event ingestion, API querying, sparse bulk export, and offline independent cryptographic re-calculation of `contentHash` and `recordHash` from extracted properties.

---

## Log Entry 15: API Error-Handling Hardening

- **Timestamp**: 2026-09-02
- **Activity**: API Error Standardization and Review
- **AI Tool / System**: Antigravity (Google DeepMind)
- **Scope & Objectives**:
  - Introduced a centralized GlobalExceptionHandler (@RestControllerAdvice) to intercept Spring validation errors.
  - Formatted expected validation errors (MethodArgumentNotValidException, ConstraintViolationException) to return controlled JSON responses.
  - Reviewed the broad handling of IllegalArgumentException in the codebase.
  - Documented that no change was made to the IllegalArgumentException handler because all current usages (in AuditService and RetentionService) strictly represent client/input validation logic.
  - Confirmed that server.error.include-message=always was deliberately not added to the configuration.
  - Executed mvn clean test resulting in 63 tests run, 0 failures, and 0 errors.

## Log Entry 16: Profile-Based Security & Rate Limiting implementation

- **Timestamp**: 2026-09-02
- **Activity**: Implementing DEV/PROD Security
- **AI Tool / System**: Antigravity (Google DeepMind)
- **Scope & Objectives**:
  - Implemented stateless API security using two profiles: dev and prod.
  - Configured Basic Authentication and default CORS for the dev profile.
  - Configured OAuth2 Resource Server (JWT validation) with explicit Audience validation for the prod profile.
  - Implemented in-memory rate limiting using Bucket4j, scoping it to authenticated principal or IP. Documented that this limitation is per-instance.
  - Updated all MockMvc tests to bypass security using @WithMockUser and imported DevSecurityConfig into isolated @WebMvcTest slices to ensure tests run smoothly with standard configurations.
  - Added new integration tests validating security success/failures, CORS preflights, and Rate Limit exhaustions.
  - Configured the JaCoCo Maven plugin to generate coverage reports.
## Log Entry 17: Security Posture Review & Corrections

- **Timestamp**: 2026-09-02
- **Activity**: Code Review and Constraint Enforcement
- **AI Tool / System**: Antigravity (Google DeepMind)
- **Scope & Objectives**:
  - Conducted a focused review on rate-limit ordering, JWT startup requirements, and CORS wildcard handling.
  - Implemented programmatic validation in ProdSecurityConfig to explicitly reject wildcard (*) origins in the prod profile, adding ProdCorsWildcardTest for verification.
  - Corrected README.md and docs/architecture.md to accurately describe the synchronous startup network dependency for OIDC JWK discovery, preventing misleading claims about fully offline JWT capability.
