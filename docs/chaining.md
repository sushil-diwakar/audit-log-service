# Tamper-Evident Hash Chain

This document outlines the design of the deterministic, tamper-evident hash chain used by the Audit Log Service (Commit #7).

## Structure
To mathematically prove the integrity and exact sequence of events, every `AuditRecord` is cryptographically chained to its predecessor. This behaves as an append-only verifiable ledger.

1. **Content Hash (`contentHash`)**: 
   - First, a deterministic SHA-256 hash of the immutable core data (actor, event type, canonicalized payload, etc.) is generated. (See `hashing.md` for specifics on payload canonicalization).
2. **Chaining (`previousHash`)**:
   - The system retrieves the `recordHash` of the immediately preceding (most recent) audit record and assigns it to the new event's `previousHash` field.
3. **Record Hash (`recordHash`)**:
   - Finally, a SHA-256 hash is generated using the formula: `SHA-256(contentHash + "|" + previousHash)`.
   - This `recordHash` acts as the definitive footprint of the event and its exact place in history, effectively sealing the chain up to that point.

## The Genesis Value
The very first record in the system has no predecessor. In this scenario, the `previousHash` is statically assigned a fixed, well-known constant: `"GENESIS"`. 

This explicit genesis value ensures the chain is mathematically closed at the origin.

## Chain Ordering
Chain continuity relies on a single deterministic timeline governed strictly by **Append Order**, completely independent of the event's business timestamp. 

1. **Event Timestamp vs Chain Position**: 
   - The `timestamp` field represents the business/event time (either provided by the client or generated as a default). It can arrive out of order or be delayed. It does **not** influence the cryptographic chain position.
   - The cryptographic chain strictly represents the order in which events were successfully appended and persisted to the database.
2. **Identifying the Chain Head**: 
   - When appending a new record, the system identifies the *true* topological chain head using an exact relational query: it finds the single existing record whose `recordHash` is not referenced by any other record's `previousHash`.
3. **Query API Presentation**: 
   - When retrieving records via `GET /audit/events`, they are sorted by `timestamp ASC, id ASC`. This is purely a presentation-layer convenience for querying and timeline visualization. It is **not** the underlying cryptographic chain sequence.

## Concurrency Strategy
A major challenge with hash chaining is handling concurrent writes (e.g., Thread A and Thread B simultaneously attempting to append to Record X).

**Chosen Approach: Optimistic Unique Constraint**
- We enforce a database-level `UNIQUE` constraint on the `previousHash` column.
- In a strictly linear chain, a specific hash can only act as the "previous hash" for *exactly one* subsequent record.
- If two threads concurrently read the latest record (Record X) and simultaneously try to `saveAndFlush` their new events referencing Record X's hash, the database will accept one and reject the other with a `DataIntegrityViolationException`.
- The `AuditService` catches this violation and executes a lightweight loop (up to 3 retries), re-fetching the newly established chain head and trying again.

### Limitations & Tradeoffs
- **Throughput**: Because the chain is strictly linear and pessimistic/optimistic locking forces serialization, throughput is inherently limited by the database's latency per write. Highly concurrent burst writes will experience artificial contention and backoff delays. 
- **Scale**: For a prototype or low-to-medium write environments, this approach is clean, database-safe, and avoids heavy distributed queuing infrastructure (like Kafka). In a hyper-scale production environment, a buffering architecture or localized mini-chains (e.g., partitioned by tenant or actor) might be necessary to alleviate the single-chain bottleneck.
