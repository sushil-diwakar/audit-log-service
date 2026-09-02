# Audit Log Retention (Scenario B)

## Design Decision: Soft Archival

For regulatory systems secured by a cryptographic hash chain, standard physical deletion poses a severe architectural problem: removing an audit record physically breaks the temporal linkage of the hash chain. A broken chain makes it impossible to verify the integrity of the subsequent records.

To satisfy both the requirement for lifecycle management and the immutable nature of the hash chain, this system uses **Soft Archival**. 

When a retention policy is executed, records older than a specific cutoff are not deleted. Instead, they transition their internal `status` from `ACTIVE` to `ARCHIVED`.

## Behavior & Properties

1. **Hash Chain Preservation**:
   - Because `status` is explicitly excluded from the deterministic payload hashed by the `HashService`, transitioning a record to `ARCHIVED` does not alter its `contentHash`.
   - The `previousHash` and `recordHash` fields are entirely untouched. 
   - `GET /audit/verify` continues to treat `ARCHIVED` records as intact components of the chain, preventing false positive verification failures.

2. **Querying**:
   - `GET /audit/events` continues to return both `ACTIVE` and `ARCHIVED` records. Archived records still represent historically factual audit events and remain fully searchable within the platform.

3. **Idempotency**:
   - The archival process operates using a bulk `UPDATE` mechanism that explicitly targets only `ACTIVE` records. Running the retention process multiple times with the same cutoff time is perfectly safe and highly efficient.

4. **Security**:
   - No `DELETE`, `PUT`, or `PATCH` endpoints are exposed to the public API.
   - The retention operation is strictly controlled via `POST /audit/retention/archive?before=<timestamp>` and cannot alter the `eventType`, `actorId`, `payload`, or cryptographic hashes of any record.

## Timestamp Selection Tradeoff

The retention policy currently evaluates the caller-supplied business `timestamp` field rather than the database-assigned ingestion time (`createdAt`). 

**Tradeoff & Limitations:**
Because the event `timestamp` is dictated by the client, a malicious or misconfigured client could backdate an event to artificially force it into an immediate `ARCHIVED` state upon creation, assuming the retention job runs frequently.
For production applications subject to strict SEC/FINRA compliance rules (where WORM storage compliance is required), retention policies often evaluate the strict server-side `createdAt` ingestion time instead to prevent backdating circumvention. This prototype uses the event `timestamp` as requested for scenario demonstration.
