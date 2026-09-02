# Audit Log Hashing Strategy

This document details the deterministic hashing strategy used by the Audit Log Service to ensure data integrity and tamper-evidence (Commit #6 / Scenario A).

## Overview
The service uses **SHA-256** to compute a cryptographic `contentHash` for each `AuditRecord`. This hash acts as a digital fingerprint of the event's immutable content.

## Included Fields
The content hash is strictly calculated from the event's core, immutable properties:
- `eventType`
- `actorId`
- `resourceType`
- `resourceId`
- `payload` (Structured JSON)
- `timestamp`

These fields represent the actual intent and data of the audit event at the time it occurred.

## Excluded Fields
The following fields are deliberately **excluded** from the content hash calculation:
- `id`
- `createdAt`
- `status`
- `previousHash`
- `recordHash`

### Why exclude database-generated fields?
The content hash must be verifiable independently of the database state. 
- Fields like `id` and `createdAt` are generated at the time of insertion into a specific database instance. If the log is exported, migrated, or verified externally before persistence, these fields might be unavailable or differ.
- `status` reflects the current lifecycle of the record (e.g., ACTIVE vs REDACTED) and may change, but the core event content it represents never changes.
- `previousHash` and `recordHash` are part of the chaining mechanism and isolating the content hash ensures clean separation of concerns.

## Canonicalization
To guarantee that the exact same audit event always produces the exact same SHA-256 hash across different languages, platforms, or HTTP clients, the event properties are canonicalized before hashing.

1. **Fixed Property Ordering:** The top-level fields of the record are mapped into a structured JSON string in strict alphabetical order.
2. **Deterministic Payload Sorting:** JSON `payload` objects often suffer from unpredictable key ordering (e.g., `{"a":1, "b":2}` vs `{"b":2, "a":1}`). The hashing service recursively intercepts all JSON objects in the payload and orders their properties alphabetically.
3. **Array Order Preservation:** Unlike object properties, JSON arrays maintain their original element ordering because array order is semantically meaningful.
4. **Consistent Timestamps:** The `timestamp` field is explicitly formatted as a standard ISO-8601 string (e.g., `2024-01-01T12:00:00Z`).
5. **Explicit Nulls:** If any field is missing, it is explicitly serialized as a JSON `null`.

By hashing this tightly controlled canonical JSON string, the service ensures that functionally equivalent inputs strictly result in identical SHA-256 hashes.
