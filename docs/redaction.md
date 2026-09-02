# Audit Log Structured Redaction (Scenario B)

## Goal
The audit log service provides a way to redact sensitive PII/PCI fields from historical events using a JSON Pointer path mechanism, while definitively preserving the topological order and verification of the cryptographic hash chain.

## Design

### Cryptographic Commitment (`contentHash`)
Normally, In a hash-chain audit log, the payload content dictates the `contentHash`, which dictates the `recordHash`. 
Redaction fundamentally alters the payload, which would normally cascade and invalidate all subsequent `recordHash` links in the chain (destroying the integrity proof).

To solve this, the service persists the **original** `contentHash` alongside each event at creation. 
* The `contentHash` serves as the permanent cryptographic commitment to the original unredacted payload. 
* The `recordHash` chain is anchored strictly to this `contentHash`.

### Structured JSON Redaction
Rather than a destructive text-replacement, the API `POST /audit/events/{id}/redact` accepts JSON Pointer paths.
* It replaces the specific node with a structured marker: `{"redacted": true}`.
* It leaves all other nested fields, objects, and arrays structurally intact.
* It changes the record's internal status to `REDACTED`.

### Atomicity & Validation
Redaction requests are strictly all-or-nothing. 
* Prior to modifying any fields, the service validates all requested paths.
* If any JSON Pointer syntax is invalid or if any targeted path does not exist in the record's payload, the entire redaction request is aborted immediately (returning `HTTP 400 Bad Request`).
* This guarantees partial/corrupted redactions do not occur.

### Verification Tradeoff
For `REDACTED` records, the `ChainVerificationService` **does not** recalculate the payload content hash (since the plaintext is gone). 
Instead, it verifies that the securely persisted `contentHash` matches the required format, and re-verifies that the `recordHash` mathematically binds to it and the `previousHash`.

**Limitation**:
* The original `contentHash` is preserved as the cryptographic commitment.
* The `recordHash` chain remains verifiable after redaction.
* The original payload cannot be independently re-hashed after the sensitive data has been destroyed.
* If independent proof of the original payload is required, an external secure retention mechanism would be needed.
