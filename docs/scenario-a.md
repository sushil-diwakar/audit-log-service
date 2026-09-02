# Scenario A: Append-Only Immutable Audit Log

This document summarizes the completion of Scenario A for the AI-Assisted Software Engineering System — Audit Log Service. The primary objective of Scenario A was to build a tamper-evident, append-only audit log capable of maintaining absolute integrity and detecting internal database modifications.

## Implemented Requirements

The service fully satisfies the core Scenario A requirements:

### 1. Write API
- **Endpoint**: `POST /audit/events`
- Allows systems to submit audit events with `eventType`, `actorId`, `resourceType`, `resourceId`, and an unstructured JSON `payload`.
- **Timestamp Logic**: Accepts a caller-supplied event timestamp. If none is provided, the server securely assigns one (`Instant.now()`).
- **Immutability Enforcement**: The REST API exposes absolutely no `PUT`, `PATCH`, or `DELETE` endpoints, strictly enforcing an append-only surface.

### 2. Query API
- **Endpoint**: `GET /audit/events`
- Provides robust, dynamic querying and filtering.
- Supported filters: `actorId`, `eventType`, paired `resourceType` + `resourceId`, and a `from`/`to` temporal range.
- Standard Spring Data pagination (`page`, `size`) returns structured data with deterministic ordering (fallback to ID).

### 3. Cryptographic Hash Chaining
The system utilizes a topological, linked-list architecture via cryptographic hashing to provide tamper-evidence:
- **SHA-256 Hashing**: Generates a deterministic content hash from the event's immutable fields. JSON payloads are recursively canonicalized (sorting object properties alphabetically while strictly preserving semantic array order).
- **GENESIS**: The very first event inserted correctly resolves to a static `"GENESIS"` hash as its parent.
- **Append-Order Semantics**: The cryptographic chain relies strictly on actual database *append order*—not the caller's event timestamp. An event inserted today with a timestamp from 2 weeks ago correctly points to today's chain head.
- **Record Hash**: Calculated as `SHA-256(contentHash + "|" + previousHash)`, immutably fusing the event to the timeline.

Example Chain:
```
GENESIS
   ↓
Record 1 (previousHash = GENESIS)
   ↓
Record 2 (previousHash = Record 1's recordHash)
   ↓
Record 3 (previousHash = Record 2's recordHash)
```

### 4. Concurrency Approach
Multiple concurrent requests attempting to chain against the same head will cause a database-level `UNIQUE(previous_hash)` constraint violation. 
We use an **Optimistic Concurrency Strategy** that traps Spring's `DataIntegrityViolationException`, allowing concurrent threads to automatically safely re-fetch the newly advanced chain head and retry until successfully slotted.

### 5. Integrity Verification
- **Endpoint**: `GET /audit/verify`
- Executes an algorithmic traversal of the entire log in a read-only transaction.
- Detects the following tampering vectors:
  - **Content/Record Tampering** (`RECORD_HASH_MISMATCH`): Caught by dynamically recalculating hashes.
  - **Forks/Multiple Genesis** (`MULTIPLE_GENESIS`, `FORK_DETECTED`): Caught by relationship checks (and mostly prevented by DB constraints).
  - **Orphans** (`DISCONNECTED_RECORD`): Forged but unlinked records caught by verifying 100% chain coverage.

## Known Limitations & Tradeoffs
1. **Internal Boundary Trust**: The verification acts solely on internal database structures. If a highly privileged attacker deletes the entire database and rebuilds a mathematically perfect forged chain, this standalone service cannot detect the rewrite. Securing against full history replacement requires an *external anchor* (such as periodically committing the chain head to a blockchain or a secondary WORM storage system), which is outside the scope of Scenario A.
2. **Performance under extreme load**: A heavily stressed single MySQL table resolving chain heads in real-time may experience contention. The optimistic retry approach handles this safely but could impact latency at massive scale without batching techniques.
3. **Missing Features**: Scenario B & C features such as data retention parsing, archival extraction, field redaction, Kafka pub/sub, and role-based access control are actively excluded from this milestone.
