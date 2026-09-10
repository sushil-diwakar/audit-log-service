# Testing & Validation Evidence

## 1. Quality Gate

Command:
`mvn clean verify`

## 2. Test Summary

* **Total**: 133
* **Failures**: 0
* **Errors**: 0
* **Skipped**: 0

## 3. Coverage

* **Instruction**: 91%
* **Branch**: 75%

## 4. Integrity Coverage Mapping

| Integrity Requirement | Test Class | Test Scenario |
|-----------------------|------------|---------------|
| Hash-chain integrity | `VerificationIntegrationTest` | `testTamperContent_AllFields` (detects payload/timestamp/field tampering) |
| Hash-chain integrity | `VerificationIntegrationTest` | `testTamperRecordHash_DetectsRecordHashMismatch` |
| Hash-chain integrity | `VerificationIntegrationTest` | `testBrokenPreviousLink_DetectsBrokenLink` |
| Hash-chain integrity | `VerificationIntegrationTest` | `testMissingGenesis_DetectsMissingGenesis` |
| Hash-chain integrity | `VerificationIntegrationTest` | `testMultipleGenesis_DetectsMultipleGenesis` |
| Hash-chain integrity | `VerificationIntegrationTest` | `testFork_DetectsFork` |
| Hash-chain integrity | `VerificationIntegrationTest` | `testCycle_DetectsCycle` |
| Hash-chain integrity | `VerificationIntegrationTest` | `testDisconnectedOrphanRecord` |
| Deterministic Hashing | `HashServiceTest` | `testNullValuesAreDeterministic` |
| Deterministic Hashing | `HashServiceTest` | `testNestedJsonPayloadKeyOrderingIsDeterministic` |
| Deterministic Hashing | `HashServiceTest` | `testRecordHashChangesWhenPreviousHashChanges` |
| Deterministic Hashing | `HashServiceTest` | `testRecordHashChangesWhenContentHashChanges` |
| Redaction integrity | `VerificationIntegrationTest` | `testConstructMaliciousRedactionState_FailsHMAC` (HMAC tampering) |
| Redaction integrity | `VerificationIntegrationTest` | `testTamperRedaction_ModifyPayloadAfterRedaction` |
| Redaction integrity | `VerificationIntegrationTest` | `testTamperContentHash_AfterRedaction` |
| Redaction integrity | `VerificationIntegrationTest` | `testTamperRevertRedactionToActive` |
| Redaction API paths | `RedactionIntegrationTest` | `testInvalidJsonPointerSyntax` |
| Redaction API paths | `RedactionIntegrationTest` | `testMissingPathAtomicity` |
| Retention integrity | `RetentionIntegrationTest` | `testRetentionSoftArchivalAndChainIntegrity` (archive without hash mutation) |
| Export integrity | `ExportIntegrationTest` | `testSparseExportBehavior` (chain completeness omitted) |
| Export authenticity | `ExportSignatureIntegrationTest` | `testTamperAnyField_InvalidatesSignature` (RSA signature tampering) |
| Concurrent append | `ConcurrentAppendTest` | `testConcurrentAppend_DoesNotCreateFork` |
| API Verification | `VerificationApiTest` | `testValidChain_Returns200AndValidTrue` |

## 5. Security Access & Bypass Evidence

All endpoints map strictly to their `@PreAuthorize` scopes. For example:
- Unauthenticated access returns HTTP 401.
- Authenticated access without `SCOPE_audit:write` returns 403 on append operations.
- The independent verifier endpoint `POST /audit/export/verify` permits anonymous access for external auditing.

## 6. Known Testing Limitations

- **Completeness Guarantees**: We cannot formally prove that upstream systems didn't fail to emit an event; the system only guarantees the integrity of events it actually received.
- **True Concurrency**: While `ConcurrentAppendTest` simulates multi-threaded writes using an `ExecutorService`, simulating exact nanosecond race conditions across multiple application nodes hitting the same database remains difficult in standard unit/integration testing without specialized database locking emulation.
- **Sparse Exports**: A sparse/filtered export cannot natively prove global completeness without downloading the entire graph. The exported items are authenticated via RSA, but omission between records cannot be verified.
