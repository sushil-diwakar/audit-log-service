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
