package com.example.auditlog.config;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.BeanCreationException;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.test.context.ActiveProfiles;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for fail-secure configuration validation.
 * Verifies that production cannot start without critical security properties.
 */
class SecurityConfigurationValidatorTest {

    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
            .withUserConfiguration(SecurityConfigurationValidator.class)
            .withPropertyValues("spring.profiles.active=prod");

    @Test
    void testValidConfiguration_Succeeds() {
        contextRunner
                .withPropertyValues(
                        "spring.security.oauth2.resourceserver.jwt.issuer-uri=https://auth.example.com",
                        "audit.security.oauth2.audience=audit-api",
                        "audit.signature.private-key=test-private-key",
                        "audit.signature.public-key=test-public-key",
                        "audit.signature.key-id=prod-key-001",
                        "audit.cors.allowed-origins=https://example.com"
                )
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).hasSingleBean(SecurityConfigurationValidator.class);
                });
    }

    @Test
    void testMissingIssuerUri_FailsFast() {
        contextRunner
                .withPropertyValues(
                        "spring.security.oauth2.resourceserver.jwt.issuer-uri=",
                        "audit.security.oauth2.audience=audit-api",
                        "audit.signature.private-key=test-private-key",
                        "audit.signature.public-key=test-public-key",
                        "audit.signature.key-id=prod-key-001",
                        "audit.cors.allowed-origins=https://example.com"
                )
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .hasRootCauseInstanceOf(IllegalStateException.class)
                            .hasMessageContaining("OIDC_ISSUER_URI");
                });
    }

    @Test
    void testMissingAudience_FailsFast() {
        contextRunner
                .withPropertyValues(
                        "spring.security.oauth2.resourceserver.jwt.issuer-uri=https://auth.example.com",
                        "audit.security.oauth2.audience=",
                        "audit.signature.private-key=test-private-key",
                        "audit.signature.public-key=test-public-key",
                        "audit.signature.key-id=prod-key-001",
                        "audit.cors.allowed-origins=https://example.com"
                )
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .hasRootCauseInstanceOf(IllegalStateException.class)
                            .hasMessageContaining("OIDC_AUDIENCE");
                });
    }

    @Test
    void testMissingSignatureKeys_FailsFast() {
        contextRunner
                .withPropertyValues(
                        "spring.security.oauth2.resourceserver.jwt.issuer-uri=https://auth.example.com",
                        "audit.security.oauth2.audience=audit-api",
                        "audit.signature.private-key=",
                        "audit.signature.public-key=test-public-key",
                        "audit.signature.key-id=prod-key-001",
                        "audit.cors.allowed-origins=https://example.com"
                )
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .hasRootCauseInstanceOf(IllegalStateException.class)
                            .hasMessageContaining("AUDIT_SIGNATURE_PRIVATE_KEY");
                });
    }

    @Test
    void testDefaultKeyId_FailsFast() {
        contextRunner
                .withPropertyValues(
                        "spring.security.oauth2.resourceserver.jwt.issuer-uri=https://auth.example.com",
                        "audit.security.oauth2.audience=audit-api",
                        "audit.signature.private-key=test-private-key",
                        "audit.signature.public-key=test-public-key",
                        "audit.signature.key-id=default-key-id",
                        "audit.cors.allowed-origins=https://example.com"
                )
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .hasRootCauseInstanceOf(IllegalStateException.class)
                            .hasMessageContaining("AUDIT_SIGNATURE_KEY_ID");
                });
    }

    @Test
    void testMissingCorsOrigins_FailsFast() {
        contextRunner
                .withPropertyValues(
                        "spring.security.oauth2.resourceserver.jwt.issuer-uri=https://auth.example.com",
                        "audit.security.oauth2.audience=audit-api",
                        "audit.signature.private-key=test-private-key",
                        "audit.signature.public-key=test-public-key",
                        "audit.signature.key-id=prod-key-001",
                        "audit.cors.allowed-origins="
                )
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .hasRootCauseInstanceOf(IllegalStateException.class)
                            .hasMessageContaining("PROD_ALLOWED_ORIGINS");
                });
    }

    @Test
    void testMultipleMissingProperties_FailsFast() {
        contextRunner
                .withPropertyValues(
                        "spring.security.oauth2.resourceserver.jwt.issuer-uri=",
                        "audit.security.oauth2.audience=",
                        "audit.signature.private-key=",
                        "audit.signature.public-key=",
                        "audit.signature.key-id=default-key-id",
                        "audit.cors.allowed-origins="
                )
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .hasRootCauseInstanceOf(IllegalStateException.class);
                });
    }
}
