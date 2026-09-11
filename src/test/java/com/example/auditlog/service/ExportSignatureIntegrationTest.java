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
import org.springframework.web.server.ResponseStatusException;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

@SpringBootTest(properties = {
    "DEV_USER=test", "DEV_PASSWORD=test", 
    "spring.datasource.url=jdbc:h2:mem:auditdb;DB_CLOSE_DELAY=-1", 
    "spring.datasource.username=sa", "spring.datasource.driver-class-name=org.h2.Driver", "spring.datasource.password="
})
@ActiveProfiles("dev")
class ExportSignatureIntegrationTest {

    @DynamicPropertySource
    static void dynamicProperties(DynamicPropertyRegistry registry) throws Exception {
        java.security.KeyPairGenerator generator = java.security.KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        java.security.KeyPair pair = generator.generateKeyPair();
        String pub = java.util.Base64.getEncoder().encodeToString(pair.getPublic().getEncoded());
        String priv = java.util.Base64.getEncoder().encodeToString(pair.getPrivate().getEncoded());
        registry.add("audit.signature.public-key", () -> pub);
        registry.add("audit.signature.private-key", () -> priv);
        registry.add("audit.signature.key-id", () -> "test-key-dynamic");
        registry.add("audit.redaction.hmac-secret", () -> java.util.UUID.randomUUID().toString());
        registry.add("spring.datasource.url", () -> "jdbc:h2:mem:auditdb;DB_CLOSE_DELAY=-1");
        registry.add("spring.datasource.username", () -> "sa");
        registry.add("spring.datasource.password", () -> "");
        registry.add("spring.datasource.driver-class-name", () -> "org.h2.Driver");
        registry.add("DEV_USER", () -> "test");
        registry.add("DEV_PASSWORD", () -> "test");
    }

    @Autowired
    private ExportSignatureService signatureService;

    @Autowired
    private ObjectMapper mapper;

    private ExportBundle createSampleBundle() throws Exception {
        ExportRecord record = ExportRecord.builder()
                .id(UUID.fromString("123e4567-e89b-12d3-a456-426614174000"))
                .eventType("TEST")
                .actorId("actor1")
                .resourceType("RES")
                .resourceId("res1")
                .payload(mapper.readTree("{\"k1\":\"v1\", \"k2\":\"v2\"}"))
                .timestamp(Instant.parse("2025-01-01T00:00:00Z"))
                .contentHash("hash1")
                .previousHash("hash0")
                .recordHash("hash2")
                .build();

        List<ExportRecord> records = new ArrayList<>();
        records.add(record);

        ExportMetadata meta = ExportMetadata.builder()
                .generatedAt(Instant.parse("2025-01-01T00:00:00Z"))
                .query(new ExportMetadata.QueryFilter("actor1", null))
                .recordCount(1)
                .firstExportedRecordPreviousHash("hash0")
                .firstExportedRecordHash("hash2")
                .lastExportedRecordHash("hash2")
                .globalChainTipHash("hash3")
                .build();

        return ExportBundle.builder().metadata(meta).records(records).build();
    }

    @Test
    void testValidSignatureVerifies() throws Exception {
        ExportBundle bundle = createSampleBundle();
        signatureService.signBundle(bundle);

        assertThat(bundle.getMetadata().getSignature()).isNotNull();
        assertThat(bundle.getMetadata().getSignature().getSignatureValue()).isNotBlank();

        boolean isValid = signatureService.verifySignature(bundle);
        assertThat(isValid).isTrue();
    }

    @Test
    void testTamperAnyField_InvalidatesSignature() throws Exception {
        ExportBundle bundle = createSampleBundle();
        signatureService.signBundle(bundle);

        bundle.getRecords().get(0).setEventType("TAMPERED");
        assertThat(signatureService.verifySignature(bundle)).isFalse();
        bundle.getRecords().get(0).setEventType("LOGIN"); // revert

        bundle.getRecords().get(0).setActorId("TAMPERED");
        assertThat(signatureService.verifySignature(bundle)).isFalse();
        bundle.getRecords().get(0).setActorId("user1"); // revert

        bundle.getRecords().get(0).setResourceId("TAMPERED");
        assertThat(signatureService.verifySignature(bundle)).isFalse();
        bundle.getRecords().get(0).setResourceId("res1"); // revert

        bundle.getRecords().get(0).setPayload(new com.fasterxml.jackson.databind.ObjectMapper().readTree("{\"tampered\": true}"));
        assertThat(signatureService.verifySignature(bundle)).isFalse();
        bundle.getRecords().get(0).setPayload(new com.fasterxml.jackson.databind.ObjectMapper().readTree("{\"action\":\"test\"}")); // revert

        bundle.getRecords().get(0).setPreviousHash("TAMPERED");
        assertThat(signatureService.verifySignature(bundle)).isFalse();
        bundle.getRecords().get(0).setPreviousHash("GENESIS"); // revert

        bundle.getRecords().get(0).setContentHash("TAMPERED");
        assertThat(signatureService.verifySignature(bundle)).isFalse();
        // and so on...
    }

    @Test
    void testTamperMetadata_InvalidatesSignature() throws Exception {
        ExportBundle bundle = createSampleBundle();
        signatureService.signBundle(bundle);

        bundle.getMetadata().setGlobalChainTipHash("TAMPERED");
        assertThat(signatureService.verifySignature(bundle)).isFalse();
    }

    @Test
    void testDifferentBundlesHaveDifferentSignatures() throws Exception {
        ExportBundle bundle1 = createSampleBundle();
        signatureService.signBundle(bundle1);

        ExportBundle bundle2 = createSampleBundle();
        bundle2.getRecords().get(0).setActorId("actor2");
        signatureService.signBundle(bundle2);

        assertThat(bundle1.getMetadata().getSignature().getSignatureValue())
                .isNotEqualTo(bundle2.getMetadata().getSignature().getSignatureValue());
    }

    @Test
    void testCanonicalizationObjectOrdering_DoesNotBreakSignature() throws Exception {
        ExportBundle bundle1 = createSampleBundle();
        bundle1.getRecords().get(0).setPayload(mapper.readTree("{\"a\":1, \"b\":2}"));
        signatureService.signBundle(bundle1);

        ExportBundle bundle2 = createSampleBundle();
        bundle2.getRecords().get(0).setPayload(mapper.readTree("{\"b\":2, \"a\":1}"));
        signatureService.signBundle(bundle2);

        assertThat(bundle1.getMetadata().getSignature().getSignatureValue())
                .isEqualTo(bundle2.getMetadata().getSignature().getSignatureValue());
    }

    @Test
    void testCanonicalizationArrayOrdering_BreaksSignature() throws Exception {
        ExportBundle bundle1 = createSampleBundle();
        bundle1.getRecords().get(0).setPayload(mapper.readTree("{\"arr\":[1,2]}"));
        signatureService.signBundle(bundle1);

        ExportBundle bundle2 = createSampleBundle();
        bundle2.getRecords().get(0).setPayload(mapper.readTree("{\"arr\":[2,1]}"));
        signatureService.signBundle(bundle2);

        assertThat(bundle1.getMetadata().getSignature().getSignatureValue())
                .isNotEqualTo(bundle2.getMetadata().getSignature().getSignatureValue());
    }

    @Test
    void testWrongKeyVersion_FailsVerification() throws Exception {
        ExportBundle bundle = createSampleBundle();
        signatureService.signBundle(bundle);

        bundle.getMetadata().getSignature().setCanonicalizationVersion("v2");
        assertThat(signatureService.verifySignature(bundle)).isFalse();
    }
}
