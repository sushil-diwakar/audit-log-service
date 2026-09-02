# AI Usage Log

This document tracks all AI-assisted interactions, architectural contributions, code generation, and test development activities for the **AI-Assisted Software Engineering System â€” Audit Log Service** project.

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