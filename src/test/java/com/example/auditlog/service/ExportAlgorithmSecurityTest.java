package com.example.auditlog.service;

import com.example.auditlog.dto.ExportBundle;
import com.example.auditlog.dto.ExportMetadata;
import com.example.auditlog.dto.ExportRecord;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.security.test.context.support.WithMockUser;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Security tests for export signature algorithm validation.
 * Ensures algorithm substitution attacks are prevented.
 */
@SpringBootTest(properties = {
    "DEV_USER=test", "DEV_PASSWORD=test",
    "spring.datasource.url=jdbc:h2:mem:testdb;DB_CLOSE_DELAY=-1",
    "spring.datasource.username=sa",
    "spring.datasource.driver-class-name=org.h2.Driver",
    "spring.datasource.password="
})
@ActiveProfiles("dev")
@TestPropertySource(properties = "spring.jpa.hibernate.ddl-auto=create-drop")
class ExportAlgorithmSecurityTest {

    @org.springframework.test.context.DynamicPropertySource
    static void dynamicProperties(org.springframework.test.context.DynamicPropertyRegistry registry) throws Exception {
        java.security.KeyPairGenerator generator = java.security.KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        java.security.KeyPair pair = generator.generateKeyPair();
        registry.add("audit.signature.public-key", () -> java.util.Base64.getEncoder().encodeToString(pair.getPublic().getEncoded()));
        registry.add("audit.signature.private-key", () -> java.util.Base64.getEncoder().encodeToString(pair.getPrivate().getEncoded()));
        registry.add("audit.signature.key-id", () -> "test-key-algo");
        registry.add("audit.redaction.hmac-secret", () -> java.util.UUID.randomUUID().toString());
    }

    @Autowired
    private ExportSignatureService exportSignatureService;

    @Autowired
    private ObjectMapper objectMapper;

    @Test
    @WithMockUser(username = "actor-all", authorities = {"SCOPE_audit:read", "SCOPE_audit:write", "SCOPE_audit:redact", "SCOPE_audit:archive", "SCOPE_audit:export", "SCOPE_audit:verify", "ROLE_ADMIN"})
    void testAlgorithmSubstitution_WeakAlgorithm_Rejected() {
        // Create a bundle with legitimate signature but weak algorithm
        ExportBundle bundle = createMockBundle();

        // Sign with legitimate algorithm first
        exportSignatureService.signBundle(bundle);

        // Attack: Substitute algorithm to SHA1withRSA (weak)
        bundle.getMetadata().getSignature().setAlgorithm("SHA1withRSA");

        // Verification should reject due to algorithm mismatch
        boolean valid = exportSignatureService.verifySignature(bundle);

        assertThat(valid).isFalse();
    }

    @Test
    @WithMockUser(username = "actor-all", authorities = {"SCOPE_audit:read", "SCOPE_audit:write", "SCOPE_audit:redact", "SCOPE_audit:archive", "SCOPE_audit:export", "SCOPE_audit:verify", "ROLE_ADMIN"})
    void testAlgorithmSubstitution_NonExistentAlgorithm_Rejected() {
        // Create a bundle with legitimate signature
        ExportBundle bundle = createMockBundle();
        exportSignatureService.signBundle(bundle);

        // Attack: Substitute to non-existent algorithm
        bundle.getMetadata().getSignature().setAlgorithm("FAKE-ALGORITHM");

        // Verification should reject
        boolean valid = exportSignatureService.verifySignature(bundle);

        assertThat(valid).isFalse();
    }

    @Test
    @WithMockUser(username = "actor-all", authorities = {"SCOPE_audit:read", "SCOPE_audit:write", "SCOPE_audit:redact", "SCOPE_audit:archive", "SCOPE_audit:export", "SCOPE_audit:verify", "ROLE_ADMIN"})
    void testAlgorithmSubstitution_MD5Algorithm_Rejected() {
        // Create a bundle
        ExportBundle bundle = createMockBundle();
        exportSignatureService.signBundle(bundle);

        // Attack: Substitute to MD5 (broken hash)
        bundle.getMetadata().getSignature().setAlgorithm("MD5withRSA");

        // Verification should reject
        boolean valid = exportSignatureService.verifySignature(bundle);

        assertThat(valid).isFalse();
    }

    @Test
    @WithMockUser(username = "actor-all", authorities = {"SCOPE_audit:read", "SCOPE_audit:write", "SCOPE_audit:redact", "SCOPE_audit:archive", "SCOPE_audit:export", "SCOPE_audit:verify", "ROLE_ADMIN"})
    void testLegitimateAlgorithm_Accepted() {
        // Create and sign bundle with correct algorithm
        ExportBundle bundle = createMockBundle();
        exportSignatureService.signBundle(bundle);

        // Verification should succeed with legitimate SHA256withRSA
        boolean valid = exportSignatureService.verifySignature(bundle);

        assertThat(valid).isTrue();
        assertThat(bundle.getMetadata().getSignature().getAlgorithm()).isEqualTo("SHA256withRSA");
    }

    private ExportBundle createMockBundle() {
        List<ExportRecord> records = new ArrayList<>();

        ExportRecord record = ExportRecord.builder()
                .id(java.util.UUID.randomUUID())
                .eventType("TEST_EVENT")
                .actorId("actor-1")
                .resourceType("SYS")
                .resourceId("1")
                .contentHash("hash1")
                .previousHash("GENESIS")
                .recordHash("rhash1")
                .timestamp(java.time.Instant.now())
                .build();

        records.add(record);

        ExportMetadata.QueryFilter query = ExportMetadata.QueryFilter.builder()
                .actorId("actor-1")
                .build();

        ExportMetadata metadata = ExportMetadata.builder()
                .recordCount(1)
                .generatedAt(java.time.Instant.now())
                .query(query)
                .build();

        return ExportBundle.builder()
                .records(records)
                .metadata(metadata)
                .build();
    }
}
