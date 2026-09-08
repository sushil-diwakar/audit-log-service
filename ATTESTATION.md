# Project Attestation

## Candidate & Submission Details

* **Full Name**: Sushil Diwakar
* **Email**: [sushildiwakar290@gmail.com](mailto:sushildiwakar290@gmail.com)
* **Assignment Title**: AI-Assisted Software Engineering System – Audit Log Service
* **Start Date**: 2026-09-01
* **Submission Date**: 2026-09-08

## Submission & Revision

* **Repository URL**: https://github.com/sushil-diwakar/audit-log-service.git
* **Branch**: main
* **Final Git Revision**: 0e095cd111dade16a64e8d54b0ad0b40974daf51
* **Description**: Final submission including security hardening, redaction integrity remediation, comprehensive authorization logic, and an expanded test suite.

## Attestation Statement

I, Sushil Kumar Diwakar, attest that this submission is my own individual work, completed on my own machine and accounts, and that it honestly reflects my development process and use of AI.

## AI Usage and Engineering Ownership

* **AI Assistance**: Antigravity was utilized during the development of this service. Its usage and scope are honestly and transparently documented in the AI Usage Document (`docs/AI-USAGE.md`).
* **Implementation & Testing**: AI assisted with implementation suggestions, code generation, and test scenarios.
* **Review Process**: I critically evaluated AI-generated code, tests, and architecture suggestions. No AI output was blindly accepted without manual verification against the assignment requirements. Generated code/tests were validated against requirements.
* **Quality Gate**: The complete Maven quality gate (`mvn clean verify`) was executed locally to ensure all tests passed.
* **Engineering Ownership**: Final engineering decisions, implementation details, testing strategy, and limitations remain my responsibility.

## Test Execution & Coverage Results

* **Total Tests Executed**: 130
* **Failures**: 0
* **Errors**: 0
* **Skipped**: 0
* **Build Result**: SUCCESS
* **JaCoCo Instruction Coverage**: 91%
* **JaCoCo Branch Coverage**: 75%

## Evidence & Verification

* **Hash-chain integrity**: Implemented in `HashService` and `ChainVerificationService`. Tampering scenarios are tested in `HashChainIntegrationTest` and `HashServiceTest`.
* **Redaction integrity**: Implemented in `RedactionService` utilizing HMAC-SHA-256 to validate the defined redaction transition. Adversarial redaction scenarios (overlapping paths, forgery) are tested in `RedactionIntegrationTest` and `ValidationIntegrationTest`.
* **Retention**: Implemented in `RetentionService` with a scheduled cleanup task. Tests proving archived records preserve integrity are located in `RetentionIntegrationTest`.
* **Bulk export**: Implemented in `ExportService` which filters the chain. Integrity and limitations of sparse exports are verified in `ExportIntegrationTest`.
* **Digital signature**: Implemented in `ExportSignatureService` using RSA/SHA-256 for export bundle signing and offline verification. Signature generation and tampering are tested in `ExportSignatureIntegrationTest`.
* **Security**: Implemented Basic Authentication for `dev` and JWT/OIDC for `prod` profiles via `DevSecurityConfig` and `ProdSecurityConfig`. Method-level authorization, CORS, and rate limiting (`RateLimitFilter`) are tested extensively in `EndpointAuthorizationTest`, `JwtValidationIntegrationTest`, `CorsTest`, and `RateLimitTest`.

## Integrity and Security Assurance

* The hash chain provides cryptographic integrity and linkage verification for audit records under the defined verification model.
* Structured redaction utilizes an HMAC-SHA-256 digest to validate the defined redaction transition.
* The RSA digital signature provides authenticity and integrity protection for the signed export bundle.
* These mechanisms detect unauthorized modification within their defined trust and verification model.

## Known Limitations

* An attacker with both database access and the HMAC secret could forge consistent redaction metadata.
* Production secret protection should use appropriate secret-management/KMS/HSM controls rather than environment variables alone.
* The audit service cannot prove that an upstream application actually emitted every required access event.
* A filtered or sparse export cannot independently prove the completeness of omitted historical records.
* The export signature authenticates the signed bundle but does not itself prove complete historical provenance.