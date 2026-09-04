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

@SpringBootTest(properties = {
    "DEV_USER=test", "DEV_PASSWORD=test",
    "audit.signature.key-id=test-key-1",
    "audit.signature.private-key=MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCYcAMNLx3WHc9xI8rBJKUFNDgEOyxNKnAjGRtX4pCHAQMcOUtehnMMyJo6dTPT+4fhw0V1S2D4szI0QhZoj9bn8e6rpA2uecoZ2UJenCXNFEqZsahkoOHXh+Oi+a0RTNoBmesWFGWQSiMu/QhPLJkBn29eEcu+GYveB1oMWwUXOZj6Fk0DtiiZRoI9T/QwYcUqpJ/LBweY4S/atU5ZvuMWRPEfOyjHEL/Xm6kkfK2/sc/i9FqT1HF0fkNugLo1Bjz7gYloRyUmLbuEdyA3pHVLl2Db6TpEj8HcnpZvBwkO+8s4chXY7P4HVnHErNynXvKRtk01IrY1bq3FKY7Lzr4hAgMBAAECgf9uwPN2oMUMzJvrmBW4Puem4EnSyStm5W6UEanMMNDRRer8lqQsCYONxjJIRt9hJV+UqEvO7PWHvKq9TUb6sYdy/lRqYMeP/OzZ2wBdvRW56wRIpsuyUTHFZvX9c2pLJ4s9npcvc6JXM4ZcnXtsCvsgMra3ojZl6Cm3J6BFWdxZAmENw0iLRKl9aL9Wunrr7K0E8OSlZBy78V9I8YUIoRiHdQ1Cy/Pk53pe+EM9faioBtpd6evo92OXG9b3/+qxWCi2mEtWXPYjxj27bGwA4BI31RKjdO9yEPRcAlQwYPJVVGGPGRDxdg6BeX8vSBME2qg2ol59DBPSQwgmjf1NsgECgYEAyEIIHQ6hq5YvFgot5NTWyX8slLi0R4Dg+W4Z9LPl/Sg2Ur2RXEqwh4V/vkMc7Zd8LXBnrAe/45R0nJK0Fr4lTBgZQ/HjDj5yuRPwXQSqY86fXkQ/keFsVXIqkCmnAM+Cy8OPC+JYm4pN2g5ykPqTR63Lm1R0r9tvui2YjnG7IDECgYEAwt5lzzDhR6roTOQGyET25FlqZnqIwqyR9WwsIqAjCt+IUFFbDZl527oYSu96Ckbr/L6RylENQslUwkdgEJ5u6I0JSw+i/XBaJCaqVeFdD/u5rJxwcBdv8rYzw+8RZNv+5XWam8yQQYBucERL1OVS/sEbcQVEpM/lAMmvFpGQcPECgYAGKQHW4vxWKuiH5QhEYce5qw/UA1qIWI6THa/utxn8D6CcKvitvh5wDMtBLw9Uv7QyMaL+x74/YfG0X07q5C6BiLw+OtKhPYqJ5vMd6WbUaya7352U/zo15q0ogh+BBuEfI4Ti+LOBFWAPtSIRE6Q0MERzIsX0Iuvs7jojJ5x6AQKBgQCKnJl8pH9KdDZjIzvzzqJz0WqO1JBdMVVtZnGKe7ARdulGgGgtJ0N32UqYWvnLP6FzGbcoWzj8jatdulmJ2Lh5cIDwxIGilv13g41cIz8INH1hW7Ha+cDmu1XdBDuyK46Hd3zvX7Yo8YsdDmeGW00K6x9y6FVoinyRb+S8P/SncQKBgQCq4f/996kpehmS9NHeN5R10UgFEdl9l/2nM1MMQWV2oxIc6LInW/ATRCtuGaXfceefBdJ4NPAzBrm8k8I22pVuO6HLNW1Kqpo5wYJ7zFjeplZgp6crVVZg15NI4gQS2PcV4S4zbS1vZ3/FQDWhyB/UXWQqb6XjFj1hPJSRaS0Spg==",
    "audit.signature.public-key=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmHADDS8d1h3PcSPKwSSlBTQ4BDssTSpwIxkbV+KQhwEDHDlLXoZzDMiaOnUz0/uH4cNFdUtg+LMyNEIWaI/W5/Huq6QNrnnKGdlCXpwlzRRKmbGoZKDh14fjovmtEUzaAZnrFhRlkEojLv0ITyyZAZ9vXhHLvhmL3gdaDFsFFzmY+hZNA7YomUaCPU/0MGHFKqSfywcHmOEv2rVOWb7jFkTxHzsoxxC/15upJHytv7HP4vRak9RxdH5DboC6NQY8+4GJaEclJi27hHcgN6R1S5dg2+k6RI/B3J6WbwcJDvvLOHIV2Oz+B1ZxxKzcp17ykbZNNSK2NW6txSmOy86+IQIDAQAB"
})
@ActiveProfiles("dev")
class ExportSignatureIntegrationTest {

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
    void testTamperEventType_InvalidatesSignature() throws Exception {
        ExportBundle bundle = createSampleBundle();
        signatureService.signBundle(bundle);
        
        bundle.getRecords().get(0).setEventType("TAMPERED");
        assertThat(signatureService.verifySignature(bundle)).isFalse();
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