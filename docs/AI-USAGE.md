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
