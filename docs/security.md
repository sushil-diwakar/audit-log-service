# Security Architecture

## Authentication & Authorization
- **Dev Profile**: Basic Authentication using configurable credentials (`DEV_USER`, `DEV_PASSWORD`).
- **Prod Profile**: JWT/OIDC authentication using Spring Security OAuth2 Resource Server. `JwtDecoders.fromIssuerLocation()` performs startup OIDC discovery (requires reachable issuer infrastructure).
- **Endpoint Protection**: All API endpoints (except `/v3/api-docs` and `/swagger-ui`) require authentication. 
- `/audit/export/verify` is unauthenticated (anonymous) as it strictly verifies a submitted disconnected export bundle without exposing internal state.
- **Authorization Matrix**:
  - `POST /audit/events` -> `audit:write`
  - `GET /audit/events` -> `audit:read`
  - `POST /audit/events/{id}/redact` -> `audit:redact`
  - `POST /audit/retention/archive` -> `audit:archive`
  - `GET /audit/export` -> `audit:export`
  - `GET /audit/verify` -> `audit:verify`

## Cryptography & Secrets
- **Secrets Management**: No default DB credentials. `DEV_USER` and DB details must be supplied via environment variables. `HMAC-SHA-256` redaction keys and RSA keys are externalized.
- **Redaction HMAC**: Binds redaction metadata to the payload, ensuring that redaction states cannot be arbitrarily reverted or modified without the secret key.
- **Export Digital Signatures**: Uses an RSA private key to sign the exported JSON bundle, providing off-line integrity and authenticity.
- **Hash-Chain**: Provides cryptographic lineage and detects unauthorized mutation or database fork scenarios (which are natively prevented by MySQL `UNIQUE` constraints).

## Rate Limiting & API Protections
- **Rate Limiting**: Enforced via Bucket4j per-principal (or per IP if unauthenticated). Rejects excessive traffic with `429 Too Many Requests`. OPTIONS preflight requests bypass rate limiting.
- **CORS**: Configurable allowed origins. Production profile strictly prohibits `*` wildcard origins.
- **CSRF**: Disabled because this API is purely stateless, serving token-based clients (JWT/Basic) and does not rely on browser session cookies.
- **Replay Protection**: Not explicitly enforced by the application layer; clients are expected to handle idempotency. Token expiration manages replay windows.

## Input Validation & Error Handling
- Comprehensive input validation rejects oversized strings, missing fields, malformed JSON, invalid UUIDs, and overlapping or root-level JSON Pointers for redaction.
- `GlobalExceptionHandler` ensures that stack traces, SQL syntax, or internal system paths never leak in response bodies.

## Operational Security & Limitations
- **Limitations**: The system assumes external network security (HTTPS/TLS) and secure secret management. Compromise of both the database and the HMAC secret defeats the internal cryptographic model.
- **Global Completeness**: The sparse export proves individual lineage but intentionally lacks mechanisms to prove global database completeness. True global completeness requires verifying the full sequential database chain.
- **Security-event Ledger**: Security auditability is limited; we do not audit security failures back into our own ledger to prevent recursive storms.
