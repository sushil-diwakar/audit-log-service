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
  - Utilized a highly efficient native JPA @Modifying bulk update query (rchiveOldRecords) to perform archival idempotently without loading entities into memory.
  - Preserved complete cryptographic chain integrity by ensuring status changes do not affect contentHash, previousHash, or ecordHash fields.
  - Exposed a strict internal-facing API endpoint (POST /audit/retention/archive?before=<timestamp>) explicitly preventing individual arbitrary record modifications.
  - Developed comprehensive integration tests (RetentionIntegrationTest) mathematically asserting that all core cryptographic properties, hashes, and payload contents remain identical bit-for-bit before and after the archival transition.
  - Drafted docs/retention.md documenting the design decisions, explaining why physical deletion fundamentally compromises blockchain/hash-chain integrity, and outlining the tradeoffs of client-supplied timestamps vs. ingestion-time logic.
 
 - - -  
  
 # #   L o g   E n t r y   1 2 :   S t r u c t u r e d   R e d a c t i o n   ( C o m m i t   # 1 1 )  
  
 -   * * T i m e s t a m p * * :   2 0 2 6 - 0 9 - 0 2  
 -   * * A c t i v i t y * * :   I m p l e m e n t i n g   S c e n a r i o   C   ( S t r u c t u r e d   R e d a c t i o n )  
 -   * * A I   T o o l   /   S y s t e m * * :   A n t i g r a v i t y   ( G o o g l e   D e e p M i n d )  
 -   * * S c o p e   &   O b j e c t i v e s * * :  
     -   I m p l e m e n t e d   ` c o n t e n t H a s h `   c o l u m n   e x p l i c i t l y   p e r s i s t i n g   t h e   o r i g i n a l   c o n t e n t   c r y p t o g r a p h i c   c o m m i t m e n t .  
     -   B u i l t   ` R e d a c t i o n S e r v i c e `   e x e c u t i n g   a t o m i c   J S O N   P o i n t e r   n o d e   r e p l a c e m e n t s   ( ` { " r e d a c t e d " :   t r u e } ` )   o v e r   c o m p l e x   o b j e c t s / a r r a y s   w h i l e   p e r f e c t l y   m a i n t a i n i n g   s u r r o u n d i n g   p a y l o a d s .  
     -   I m p l e m e n t e d   h a r d   f a i l - f a s t   v a l i d a t i o n   a g a i n s t   i n v a l i d   J S O N   p o i n t e r s   a n d   m i s s i n g   p a t h s   e n s u r i n g   t r a n s a c t i o n a l   a t o m i c i t y   ( ` H T T P   4 0 0   B a d   R e q u e s t ` ) .  
     -   A d a p t e d   ` C h a i n V e r i f i c a t i o n S e r v i c e `   d i s t i n g u i s h i n g   b e t w e e n   ` A C T I V E `   a n d   ` R E D A C T E D `   r e c o r d s ,   e n s u r i n g   r e d a c t e d   s t r u c t u r e s   b y p a s s   f u l l   h a s h   r e c a l c u l a t i o n   w h i l e   p r o v i n g   m a t h e m a t i c a l l y   t h e y   r e m a i n   l e g a l l y   a n c h o r e d   t o   t h e i r   o r i g i n a l   h a s h e s .  
     -   C o m p o s e d   ` R e d a c t i o n I n t e g r a t i o n T e s t `   e x t e n s i v e l y   c o v e r i n g   d e e p   a r r a y   m o d i f i c a t i o n s ,   s y n t a x   c h e c k s ,   m u l t i p l e - f i e l d   o p e r a t i o n s ,   a n d   e x p l i c i t   A P I   t e s t i n g .  
     -   A u t h o r e d   ` d o c s / r e d a c t i o n . m d `   e x p l i c i t l y   i d e n t i f y i n g   t h e   p r i v a c y   t r a d e o f f   ( u n r e d a c t e d   p a y l o a d s   a r e   f u n d a m e n t a l l y   s t r i p p e d   a n d   m u s t   b e   s e c u r e d   o u t - o f - b a n d   f o r   l e g a l   r e - v e r i f i c a t i o n s ) .  
 