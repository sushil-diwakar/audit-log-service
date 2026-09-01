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
