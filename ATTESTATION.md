# Project Attestation



## Candidate & Submission Details



- **Full Name**: Sushil Diwakar

- **Email**: sushildiwakar290@gmail.com

- **Assignment Title**: AI-Assisted Software Engineering System - Audit Log Service

- **Final Git Revision**: 5fb3633d7d4e0de0b717d2ac7f6a65d9aeeb22ba



---



## Attestation Statement



I hereby attest that the work submitted in this repository represents an original software engineering implementation developed for the above-titled assessment. Where AI tools or third-party libraries were utilized, their scope, purpose, and integration are transparently logged in [docs/AI-USAGE.md](docs/AI-USAGE.md).



## Requirement → Implementation → Evidence Mapping



### Scenario A: Core Audit Ledger

| Requirement | Implementation | Evidence |

|-------------|----------------|----------|

| Append-only audit events | Exposes POST /audit/events. Blocked UPDATE/DELETE logic. | AuditController.createEvent, Integration tests |

| Query | Exposes GET /audit/events with pagination/filtering. | AuditController.getEvents, AuditRecordRepository queries |

| Deterministic hashing | Canonicalizes JSON before hashing to solve non-deterministic key ordering. | HashService.canonicalizeNode |

| Hash chain | Singly linked list using previousHash anchored to the database tip. | AuditService.createAuditEvent, HashChainIntegrationTest |

| Verification | Exhaustive integrity check computing hashes in-memory. | ChainVerificationService, GET /audit/verify |

| Tamper detection | Detects content or structural modifications mathematically. | VerificationIntegrationTest.testTamperContent_DetectsContentHashMismatch |



### Scenario B: Data Lifecycle

| Requirement | Implementation | Evidence |

|-------------|----------------|----------|

| Retention | Soft-archives records older than a cutoff date. | RetentionService, POST /audit/retention/archive |

| Structured redaction | Replaces targeted JSON pointer paths with {"redacted": true}. | RedactionService, POST /audit/events/{id}/redact |

| Redaction integrity | Cryptographically binds the redacted payload to the original content hash via 

edactionDigest. | HashService.calculateRedactionDigest, VerificationIntegrationTest |

| Bulk export | Exports a self-contained verifiable JSON subset threaded to the global chain. | ExportService, GET /audit/export |



### Scenario C: Regulatory Compliance

| Requirement | Implementation | Evidence |

|-------------|----------------|----------|

| Normalized compliance | Maps "access to client account data" to standard events without hardcoding domains. | ScenarioCEndToEndTest |

| Implementation mapping | Uses 

esourceType=CLIENT_ACCOUNT and eventType=ACCOUNT_READ. | README.md Scenario Summaries |

| Scope boundaries & Assumptions | Assumes external upstream systems are responsible for completeness. | README.md Limitations |



### Security & Hardening

| Requirement | Implementation | Evidence |

|-------------|----------------|----------|

| Authentication | Profile-based: Basic Auth (dev), OAuth2 Resource Server (prod). | DevSecurityConfig, ProdSecurityConfig |

| Authorization | Scope-based authorization using @PreAuthorize. | MethodSecurityConfig, AuthorizationTest |

| CORS | Profile-specific origins. Wildcards blocked in prod. | ProdCorsWildcardTest |

| Rate limiting | In-memory token bucket via Bucket4j scoped to principal/IP. | RateLimitFilter, RateLimitTest |

| API error handling | Centralized JSON error serialization preventing stack trace leaks. | GlobalExceptionHandler |



### Testing

| Requirement | Implementation | Evidence |

|-------------|----------------|----------|

| Integration tests | Full Spring Boot context tests for scenarios. | *IntegrationTest.java files |

| Security tests | Validates scopes and CORS rules. | AuthorizationTest, RateLimitTest |

| Tampering tests | Simulates DBA SQL injection to test tamper detection. | VerificationIntegrationTest |

| Coverage | Generates JaCoCo reports verifying critical paths. | mvn clean verify output in 	arget/site/jacoco |




## Testing Evidence

Authentication and authorization enforcement are covered by integration tests that assert 401 for unauthenticated requests and 403 for authenticated requests lacking the required authority (AuthorizationTest).
Redaction integrity is covered by database-tampering tests that verify forged REDACTED states produce REDACTION_METADATA_MISMATCH (VerificationIntegrationTest.testTamperRedaction_MissingDigest_DetectsMetadataMismatch).
Chain tampering scenarios are verified through VerificationIntegrationTest, asserting CONTENT_HASH_MISMATCH and BROKEN_LINKAGE logic.
For detailed execution numbers, please refer to docs/testing.md and the final mvn clean verify output.

## Proactive Adversarial Review



Before final submission, I performed an adversarial engineering review of the service's trust boundaries and failure modes as normal engineering due diligence. The review focused on:

- **Authentication vs Authorization**: Ensured that an authenticated identity alone cannot execute sensitive compliance operations without the correct explicit scope.

- **Least Privilege**: Mapped specific OAuth2-compatible scopes (SCOPE_audit:write, SCOPE_audit:verify, etc.) to individual controller methods.

- **Database-Level Tampering & Lifecycle-State Manipulation**: Identified a threat where a DBA could bypass verification by wiping a payload and changing the row status to REDACTED.

- **Redaction Integrity**: Introduced the 

edactionDigest to mathematically prove that a redaction transition occurred legally via the application API rather than via database tampering.

- **Test Evidence**: Ensured tamper tests actually simulate database-layer manipulation bypassing the API.

- **Production Limitations**: Clearly documented memory limits for indAll() and OIDC startup constraints.



## Security Invariants



### 1. Authenticated != Automatically Authorized

Authentication simply answers "Who are you?" Authorization answers "Are you allowed to perform this operation?" The system employs OAuth2-compatible scope-based authorization. Active sessions without the exact required scope are rejected with a 403 Forbidden.



### 2. Redaction Integrity

To strengthen tamper evidence, the system cryptographically binds a legitimate redaction transition to the preserved original content commitment and the resulting redacted payload. The specific formula used is:





edactionDigest = SHA-256(originalContentHash + "|REDACTED|" + canonical(redactedPayload))



The verifier strictly requires this expected 

edactionDigest for REDACTED records. Simply changing a database row status to REDACTED is insufficient and will trigger a REDACTION_METADATA_MISMATCH.



## Human Engineering Ownership



AI-assisted development was used as an implementation accelerator, but the final design, security decisions, validation, review, and engineering sign-off remain the responsibility of the candidate.
