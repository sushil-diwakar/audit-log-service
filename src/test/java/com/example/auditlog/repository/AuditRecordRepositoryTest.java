package com.example.auditlog.repository;

import com.example.auditlog.entity.AuditRecord;
import com.example.auditlog.entity.AuditRecordStatus;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.autoconfigure.orm.jpa.TestEntityManager;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;

import java.time.Instant;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@ActiveProfiles("dev")
public class AuditRecordRepositoryTest {

    @org.springframework.test.context.DynamicPropertySource
    static void dynamicProperties(org.springframework.test.context.DynamicPropertyRegistry registry) throws Exception {
        java.security.KeyPairGenerator generator = java.security.KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        java.security.KeyPair pair = generator.generateKeyPair();
        registry.add("audit.signature.public-key", () -> java.util.Base64.getEncoder().encodeToString(pair.getPublic().getEncoded()));
        registry.add("audit.signature.private-key", () -> java.util.Base64.getEncoder().encodeToString(pair.getPrivate().getEncoded()));
        registry.add("audit.signature.key-id", () -> "test-key-dynamic");
        registry.add("audit.redaction.hmac-secret", () -> java.util.UUID.randomUUID().toString());
        registry.add("spring.datasource.url", () -> "jdbc:h2:mem:auditdb;DB_CLOSE_DELAY=-1;MODE=MySQL");
        registry.add("spring.datasource.username", () -> "sa");
        registry.add("spring.datasource.password", () -> "");
        registry.add("spring.datasource.driver-class-name", () -> "org.h2.Driver");
        registry.add("DEV_USER", () -> "test");
        registry.add("DEV_PASSWORD", () -> "test");
    }

    @Autowired
    private TestEntityManager entityManager;

    @Autowired
    private AuditRecordRepository repository;

    private final ObjectMapper mapper = new ObjectMapper();

    @Test
    void testSaveAndRetrieveAuditRecord() throws JsonProcessingException {
        // Arrange
        JsonNode jsonPayload = mapper.readTree("{\"key\": \"value\", \"action\": \"CREATE\"}");
        AuditRecord record = AuditRecord.builder()
                .eventType("USER_CREATED")
                .actorId("admin-123")
                .resourceType("User")
                .resourceId("user-456")
                .payload(jsonPayload)
                .timestamp(Instant.now())
                .previousHash("0000000000000000000000000000000000000000000000000000000000000000")
                .contentHash("b1b1a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e")
                .recordHash("a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e")
                // Status implicitly ACTIVE through Builder.Default
                .build();

        // Act
        AuditRecord savedRecord = repository.save(record);
        entityManager.flush(); // Force insert to DB
        entityManager.clear(); // Clear L1 cache to force DB fetch

        // Assert
        Optional<AuditRecord> retrievedOptional = repository.findById(savedRecord.getId());
        assertThat(retrievedOptional).isPresent();
        
        AuditRecord retrieved = retrievedOptional.get();
        assertThat(retrieved.getEventType()).isEqualTo("USER_CREATED");
        assertThat(retrieved.getActorId()).isEqualTo("admin-123");
        assertThat(retrieved.getPayload()).isNotNull();
        assertThat(retrieved.getPayload().get("action").asText()).isEqualTo("CREATE");
        assertThat(retrieved.getStatus()).isEqualTo(AuditRecordStatus.ACTIVE);
        assertThat(retrieved.getCreatedAt()).isNotNull();
    }


}
