# Testing & Validation Evidence

## 1. Quality Gate

Command:
mvn clean verify

Actual result:
BUILD SUCCESS

## 2. Test Summary

Total: 82
Failures: 0
Errors: 0
Skipped: 0

## 3. Coverage

Instruction: 87%
Branch: 70%
Line: N/A (Not strictly extracted, but high instruction coverage implies high line coverage)
Method: N/A

## 4. Authentication Evidence

Table:
| Endpoint | Scenario | Expected | Actual |
|----------|----------|----------|--------|
| POST /audit/events | Unauthenticated | 401 | 401 |
| GET /audit/events | Unauthenticated | 401 | 401 |
| GET /audit/verify | Unauthenticated | 401 | 401 |
| GET /audit/export | Unauthenticated | 401 | 401 |
| POST /audit/events/{id}/redact | Unauthenticated | 401 | 401 |
| POST /audit/retention/archive | Unauthenticated | 401 | 401 |

## 5. Authorization Evidence

Table:
| Endpoint | Authority | Wrong Authority | Correct Authority |
|----------|-----------|-----------------|-------------------|
| POST /audit/events | SCOPE_audit:write | 403 | 200/2xx |
| GET /audit/events | SCOPE_audit:read | 403 | 200/2xx |
| GET /audit/verify | SCOPE_audit:verify | 403 | 200/2xx |
| GET /audit/export | SCOPE_audit:export | 403 | 200/2xx |
| POST /audit/events/{id}/redact | SCOPE_audit:redact | 403 | 200/2xx (404 valid bypass) |
| POST /audit/retention/archive | SCOPE_audit:archive | 403 | 200/2xx |

## 6. Bypass Testing

Bypass cases tested:
- Unauthenticated access to sensitive compliance operations (401).
- Privilege escalation: e.g. read authority attempting to verify or write (403).
- All endpoints map exactly to their @PreAuthorize annotations.

## 7. Redaction Integrity

Legitimate redaction tests verify that redaction via the API correctly sets the status to REDACTED and calculates a valid 
edactionDigest.
Forged redaction tests simulate a DBA bypassing the application logic via SQL:
- Missing digest with REDACTED status triggers REDACTION_METADATA_MISMATCH.
- Invalid digest with REDACTED status triggers REDACTION_METADATA_MISMATCH.

## 8. Tamper Detection

Documented tampering tests in VerificationIntegrationTest:
- Payload manipulation (CONTENT_HASH_MISMATCH)
- Record hash manipulation (RECORD_HASH_MISMATCH)
- Previous hash manipulation (BROKEN_LINKAGE or MULTIPLE_GENESIS)

## 9. API Failure Paths

Validation tests verified using GlobalExceptionHandler:
- Missing required fields
- Invalid UUID
- Exception masking without stack trace leaks

## 10. CORS

Executable CORS tests prove:
- ProdCorsWildcardTest rejects * origin for production security.
- Preflight OPTIONS requests behave correctly based on configuration.

## 11. Rate Limiting

Executable rate-limit tests in RateLimitTest prove:
- Requests within limit succeed.
- Requests exceeding limit trigger 429 Too Many Requests.
- The limitation is explicitly in-memory per instance.

## 12. Scenario A/B/C Evidence

- **Scenario A**: Validated by ScenarioAEndToEndTest asserting append-only ledger mechanisms.
- **Scenario B**: Validated by Retention, Redaction, Export integration tests.
- **Scenario C**: Validated by ScenarioCEndToEndTest mapping ACCOUNT_READ events natively without polluting generic architecture.

## 13. Known Testing Limitations

- **Completeness Guarantees**: We cannot test or prove that upstream systems actually emit events properly, only that received events are intact.
- **Scale Limits**: Tests do not simulate multi-million row graphs which would hit OOM exceptions due to indAll().
