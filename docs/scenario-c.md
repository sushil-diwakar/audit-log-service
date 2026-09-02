# Scenario C: Audit Access to Client Account Data

## Original Stakeholder Requirement
*"Regulators need to be able to audit access to client account data."*

## Requirements & Design Analysis

### Key Ambiguities
The original statement is highly ambiguous and lacks technical boundaries:
*   **What constitutes "access"?** Does it mean read-only access (viewing a profile), write access (changing a balance/address), or both?
*   **Which actors/users/systems need to be audited?** Customer support agents, customers themselves, or internal background systems?
*   **What exactly is "client account data"?** Is it PII, financial transactions, or authentication metadata?
*   **What event details must be captured?** Do we need the exact fields that were read, the IP address of the actor, or just the timestamp?
*   **Who are the regulators/auditors?** Are they internal compliance officers, external government bodies, or automated monitoring systems?
*   **What time range/history is required?** Do they need to pull the last 30 days, or 7 years of history?
*   **What retention period is required?** 1 year, 5 years, or indefinitely?
*   **Does "audit" require completeness guarantees?** Do regulators require cryptographic proof that *no accesses were omitted*, or just proof that the provided logs weren't tampered with?

### Reasonable Prototype Assumptions
To proceed without blocking, we make the following engineering assumptions for the Audit Log Service:
*   "Access" includes both Reads (`ACCOUNT_READ`) and Writes (`ACCOUNT_MODIFIED`).
*   "Client account data" translates to a specific resource type mapping (e.g., `resourceType = "CLIENT_ACCOUNT"`).
*   Regulators/auditors are technical and will consume our existing REST APIs (`GET /audit/events` and `GET /audit/export`) to retrieve this data.
*   The system generating the access (the upstream application) is responsible for determining *when* an access occurs and invoking our API to record it.

### Clarifying Questions for Production Rollout
Before a production rollout, we must ask the business:
1.  **Data Volume**: "If we log every single time an account is viewed, we anticipate millions of events per day. Is the business prepared for the storage costs, or should we only log accesses by internal staff?"
2.  **Retention**: "Exactly how long must these specific read events be kept before they can be archived or deleted under the regulatory framework?"
3.  **Privacy/PII**: "Will the access logs themselves contain sensitive client PII, requiring us to strictly enforce the Redaction feature?"

### Normalized Acceptance Criteria
*   **AC1**: The Audit Log Service must successfully ingest events categorized as account accesses (`ACCOUNT_READ`, `ACCOUNT_MODIFIED`).
*   **AC2**: The Audit Log Service must allow auditors to query and bulk-export historical access events filtered by the specific client account identifier.
*   **AC3**: The Audit Log Service must mathematically prove to regulators that the exported access logs have not been tampered with since creation.

## System Mapping & Architecture

### Mapping to the Existing Audit Log Service
Our current generic architecture perfectly accommodates this use case without any schema changes or new endpoints:
*   **eventType** = `ACCOUNT_READ` / `ACCOUNT_MODIFIED`
*   **actorId** = The accessing user/system (e.g., a CSR identifier).
*   **resourceType** = `CLIENT_ACCOUNT`
*   **resourceId** = The specific client account identifier (e.g., an account UUID).
*   **payload** = Contextual access metadata (e.g., `{"ipAddress": "192.168.1.5", "fieldsViewed": ["ssn", "balance"]}`).
*   **timestamp** = The exact access time provided by the upstream service or defaulted by the server.

### What is Already Satisfied
*   **Event Ingestion**: `POST /audit/events` natively accepts these events and mathematically binds them into the global hash-chain.
*   **Filtering**: `GET /audit/events` supports querying by `resourceType` and `resourceId`.
*   **Bulk Export & Verification**: `GET /audit/export` supports bulk exporting an offline-verifiable timeline for any `resourceId`. `GET /audit/verify` continuously audits the entire system.
*   **Retention & Redaction**: Soft archival and payload redaction are already supported natively for these events.

### What is Intentionally Scoped Out
*   **Upstream Client Account Service**: Building the actual application that holds client data is out of scope. We only provide the generic audit ledger.
*   **IAM / Spring Security**: Authenticating the "regulator" is out of scope for this prototype. In a production deployment, an API Gateway or Security Filter would handle JWT validation before requests reach this service.
*   **UI / Dashboard**: Out of scope. We provide the API; a separate frontend/compliance team would build the regulator portal.

## Security & Compliance Limitations

### 1. The Trust Boundary Limitation
The Audit Log Service only knows what it is told. If an upstream "Client Account Service" has a bug or is compromised, and fails to emit an `ACCOUNT_READ` event to our API, the audit log will be blind to the access. 
**We can strictly prove the cryptographic integrity (tamper-evidence) of the events we receive, but we cannot cryptographically prove that an upstream service did not fail to emit a real-world access event.**

### 2. Sparse Export Completeness Limitation
If a regulator queries the export for a specific client account, the cryptography proves the exported records are authentic (tamper-evident) and correctly anchored. However, a sparse linear hash-chain cannot cryptographically detect if an administrator secretly omitted a matching record from the exported subset prior to delivery. Complete proof of omission requires different architectures (e.g., Merkle Trees/Accumulators) which fall outside the current linear hash-chain implementation.

**Conclusion**: The system guarantees *tamper-evidence* of received audit records, but cannot guarantee absolute *completeness* of all real-world account accesses.
