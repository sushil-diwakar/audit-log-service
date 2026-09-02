# Hash Chain Verification

The Audit Log Service provides a `/audit/verify` API to cryptographically verify the integrity of the entire audit chain.

## Verification Algorithm

The verifier executes the following steps deterministically in a read-only transaction:

1. **Content Integrity (Hash Recalculation)**
   The system fetches every record and recalculates its `contentHash` and `recordHash` from the immutable core data. It compares the recalculated `recordHash` against the persisted `recordHash`. Any deviation throws a `RECORD_HASH_MISMATCH`, immediately identifying records modified directly in the database.

2. **Genesis Validation**
   The system searches for records pointing to `GENESIS`. 
   - Zero genesis records (in a non-empty database) triggers `MISSING_GENESIS`.
   - More than one genesis record triggers `MULTIPLE_GENESIS`.

3. **Chain Traversal**
   Starting from the genesis record, the algorithm walks the chain by mapping `previousHash` to the next record's `recordHash`. 
   - If a `previousHash` maps to multiple records, `FORK_DETECTED` is thrown.
   - If the chain enters a cycle (impossible in a strict DAG, but validated nonetheless), `CYCLE_DETECTED` is thrown.

4. **Coverage Analysis**
   After the chain reaches its end, the verifier checks if the number of traversed records matches the total count in the database. Any unvisited records trigger a `DISCONNECTED_RECORD` violation (identifying orphans).

## Empty Chain Behavior
If the database contains 0 records, the API returns a successful verification (`valid = true`). An empty log represents a pristine state with no tampering; it is logically intact.

## Tampering Detection
This verifier successfully detects:
- Direct database row modifications (payload, actor, timestamp, etc.)
- Chain forks (multiple events claiming the same parent)
- Broken links (an event referencing a non-existent parent hash)
- Orphan insertions (forged events correctly hashed but unlinked to the main trunk)

### Important Limitations
Without an external anchoring mechanism (e.g., periodically publishing the chain head hash to a blockchain, external ledger, or signed timestamping service), an internal hash chain cannot prove that the *entire history* (or the tail end of it) was not rewritten. If a highly privileged attacker truncates the database and perfectly recalculates the hashes for the remaining chain, the internal verifier will falsely report `valid = true`. 
This prototype relies strictly on internal database bounds.
