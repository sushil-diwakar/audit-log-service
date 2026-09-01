# Client Requirements Specification

## Project: AI-Assisted Software Engineering System — Audit Log Service

This document captures our analysis and understanding of the client requirements for the tamper-evident, append-only Audit Log Service.

---

### 1. Append-Only Audit Records
- The system must enforce strict append-only semantics for audit logs.
- Direct updates (`UPDATE`) and deletions (`DELETE`) on historical audit records must be strictly disallowed at both the application and database architecture levels.
- Every ingested record becomes an immutable entry in the audit history.

---

### 2. Event Fields
Each audit record must capture a comprehensive, structured representation of an event, including:
- **Identifier**: Unique record identifier (e.g., UUID or monotonic sequence ID).
- **Timestamp**: Precise ISO-8601 UTC timestamp of event occurrence/ingestion.
- **Actor Details**: Principal/user/service responsible for initiating the action (e.g., `actorId`, `actorType`, `ipAddress`).
- **Action / Event Type**: Distinct action name or event category (e.g., `USER_LOGIN`, `FILE_DOWNLOAD`, `PERMISSION_CHANGE`).
- **Resource / Target**: Identifier and type of the entity acted upon (e.g., `resourceId`, `resourceType`).
- **Event Payload / Metadata**: Structured context or state payload (JSON format) detailing the action attributes.
- **Integrity Fields**: Previous record hash, record hash, and signature/nonce where applicable.

---

### 3. Query / Filter Requirements
- The service must provide flexible and efficient query capabilities across audit records.
- Support multi-dimensional filtering by:
  - Time range (`fromTimestamp`, `toTimestamp`)
  - Actor identifier (`actorId`, `actorType`)
  - Action / Event type (`action`)
  - Resource identifier / type (`resourceId`, `resourceType`)
- Query performance must remain predictable and index-optimized as the log grows.

---

### 4. Pagination
- Endpoints retrieving audit records must enforce robust pagination to prevent memory exhaustion and uncontrolled data dumping.
- Support standard page-based (`page`, `size`) and/or cursor-based pagination with deterministic sorting (e.g., timestamp descending/ascending + sequence ID tie-breaker).
- Total record count and navigation metadata should be provided according to API conventions.

---

### 5. Hash Chain (Tamper-Evidence)
- Implement a cryptographic hash chain mechanism (e.g., SHA-256) linking each record to its immediate predecessor.
- Calculation specification:
  - Canonicalize record content (deterministic serialization of fields).
  - Compute `currentHash = SHA-256(canonicalPayload + previousHash)`.
  - The genesis record links to a known constant seed (e.g., `0000...0000` or genesis root).
- Any post-insertion tampering, reordering, insertion, or deletion of a record invalidates the entire subsequent chain.

---

### 6. Chain Verification
- Provide an API / administrative verification routine that scans the audit log sequentially to validate cryptographic integrity.
- Verification checks:
  - Re-computes each record's hash from its canonical payload and recorded `previousHash`.
  - Checks continuity (`record[n].previousHash == record[n-1].currentHash`).
- The verification output must pinpoint any point of tampering (broken link index, timestamp, expected vs. actual hash).

---

### 7. Retention Policy Management
- Provide mechanisms to manage lifecycle and retention rules for audit data (e.g., regulatory retention windows such as 30 days, 90 days, 1 year, or 7 years).
- Retention enforcement must handle pruning or archiving safely while preserving cryptographic auditability (e.g., retaining checkpoint hashes or archival chain segments).

---

### 8. Structured Redaction
- Accommodate data privacy mandates (e.g., GDPR "Right to be Forgotten", CCPA, PII sanitization) without breaking cryptographic hash chain integrity.
- Redaction mechanism:
  - Replace sensitive payload fields with a structured redaction marker or cryptographic proof (e.g., salted hashes or blinded leaves).
  - Maintain the integrity of historical verification by verifying against the original unredacted hash commitments or redaction logs.

---

### 9. Bulk Export
- Support bulk export of audit logs for compliance audits, external SIEM ingestion, or offline archiving.
- Export formats should include structured formats such as NDJSON (Newline Delimited JSON) or CSV.
- Ensure streaming/chunked processing during export to maintain low memory overhead on large data volumes.

---

### 10. Ambiguous Compliance Reporting
- Provide an extensible reporting framework capable of handling ambiguous or evolving compliance requests.
- Generate summaries, anomaly reports, and actor audit trails structured for compliance auditors with verifiable integrity attestations.

---

### 11. Testing and Validation
- Comprehensive test coverage strategy:
  - Unit tests for hashing algorithms, canonicalization, and business services.
  - Integration tests for JPA repositories, pagination queries, and REST endpoints.
  - Verification tests deliberately simulating tampered records, broken links, and out-of-order records to guarantee accurate detection.

---

### 12. AI-Assisted Development
- Transparent integration and documentation of AI-assisted engineering practices.
- AI tools assist in:
  - Architecture and scaffolding design.
  - Test case generation and edge case discovery.
  - Documentation, compliance traceability, and code quality audits.
- Full traceability maintained in `docs/AI-USAGE.md`.
