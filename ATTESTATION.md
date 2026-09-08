# Project Attestation

## Candidate & Submission Details

* **Full Name**: Sushil Diwakar
* **Email**: [sushildiwakar290@gmail.com](mailto:sushildiwakar290@gmail.com)
* **Assignment Title**: AI-Assisted Software Engineering System — Audit Log Service
* **Start Date**: 2026-09-01
* **Submission Date**: 2026-09-08
* **Final Git Revision**: 63a899c1191f8c441a7bf51636e1a8bf8a017702

---

## Attestation Statement

I, Sushil Kumar Diwakar, attest that this submission is my own individual work, completed on my own machine and accounts, and that it honestly reflects my development process and use of AI.

## Test Execution & Coverage Results

* **Total Tests Executed**: 92
* **Failures**: 0
* **Errors**: 0
* **Skipped**: 0
* **Build Result**: SUCCESS
* **JaCoCo Instruction Coverage**: 87%
* **JaCoCo Branch Coverage**: 70%

## AI Usage and Engineering Ownership

* **AI Assistance**: AI coding tools were utilized during the development of this service. Their usage and scope are honestly and transparently documented in the AI Usage Document.

* **AI-Assisted Testing**: AI was used to suggest and generate unit, integration, security, and negative test scenarios, including authentication, authorization, tampering, redaction integrity, API failure cases, and the export digital-signature functionality.

* **Coverage & Validation**: AI was used to identify potential testing gaps and suggest additional meaningful tests. I personally verified the resulting coverage and executed the complete mvn clean verify quality gate locally (see the *Test Execution & Coverage Results* section).

* **Human Review & Non-Blind Acceptance**: I critically evaluated AI-generated code, tests, and architecture suggestions. No AI output was blindly accepted without manual verification against the assignment requirements.

* **Engineering Ownership**: I take full ownership of the final implementation, test suite, architectural decisions, and validation results.

* **Responsibility for Limitations**: Any known limitations, missing production guardrails (e.g., IAM, OOM optimizations), vulnerabilities, or prototype shortcuts remain entirely my responsibility as the engineer.

## System Integrity Claims

* The hash chain provides cryptographic integrity and linkage verification for audit records under the defined verification model.
* Structured redaction preserves the chain while using redaction metadata and digests to validate the defined redaction transition.
* The export digital signature provides authenticity and integrity protection for the signed export bundle.
* These mechanisms detect unauthorized modification within their defined trust/verification model. They do not claim absolute immutability, guaranteed completeness of upstream events, or protection against a fully privileged database administrator who can modify data and recompute cryptographic metadata.
