package com.example.auditlog.config;

import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

/**
 * Validates that critical security configurations are properly set at startup.
 * Fails fast if production security requirements are not met.
 */
@Slf4j
@Component
@Profile("prod")
@RequiredArgsConstructor
public class SecurityConfigurationValidator {

    @Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri:}")
    private String issuerUri;

    @Value("${audit.security.oauth2.audience:}")
    private String audience;

    @Value("${audit.signature.private-key:}")
    private String signaturePrivateKey;

    @Value("${audit.signature.public-key:}")
    private String signaturePublicKey;

    @Value("${audit.signature.key-id:default-key-id}")
    private String keyId;

    @Value("${audit.cors.allowed-origins:}")
    private String allowedOrigins;

    @PostConstruct
    public void validateSecurityConfiguration() {
        log.info("Validating production security configuration...");

        StringBuilder errors = new StringBuilder();

        // OAuth2 OIDC Configuration
        if (issuerUri == null || issuerUri.isBlank()) {
            errors.append("- OIDC_ISSUER_URI must be configured for production\n");
        }

        if (audience == null || audience.isBlank()) {
            errors.append("- OIDC_AUDIENCE must be configured for production (JWT audience validation)\n");
        }

        // Export Signature Configuration
        if (signaturePrivateKey == null || signaturePrivateKey.isBlank()) {
            errors.append("- AUDIT_SIGNATURE_PRIVATE_KEY must be configured for production (export signing)\n");
        }

        if (signaturePublicKey == null || signaturePublicKey.isBlank()) {
            errors.append("- AUDIT_SIGNATURE_PUBLIC_KEY must be configured for production (export verification)\n");
        }

        if ("default-key-id".equals(keyId)) {
            errors.append("- AUDIT_SIGNATURE_KEY_ID must be changed from default value in production\n");
        }

        // CORS Configuration
        if (allowedOrigins == null || allowedOrigins.isBlank()) {
            errors.append("- PROD_ALLOWED_ORIGINS must be configured for production (CORS policy)\n");
        }

        if (errors.length() > 0) {
            String errorMessage = "\n" +
                    "========================================\n" +
                    "FATAL: Production security validation failed\n" +
                    "========================================\n" +
                    "The following critical security configurations are missing:\n\n" +
                    errors.toString() +
                    "\nApplication startup aborted. Please configure all required security properties.\n" +
                    "========================================\n";

            log.error(errorMessage);
            throw new IllegalStateException("Production security configuration validation failed. Missing required security properties.");
        }

        log.info("Production security configuration validation passed");
    }
}
