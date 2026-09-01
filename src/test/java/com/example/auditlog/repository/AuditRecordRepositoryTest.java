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

@DataJpaTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE) // Use real MySQL database
class AuditRecordRepositoryTest {

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

    @Test
    void testCustomQueryMethods() throws JsonProcessingException {
        // Arrange
        Instant now = Instant.now();
        JsonNode jsonPayload = mapper.readTree("{\"docName\": \"secret.txt\"}");
        AuditRecord record = AuditRecord.builder()
                .eventType("DOCUMENT_READ")
                .actorId("user-789")
                .resourceType("Document")
                .resourceId("doc-001")
                .payload(jsonPayload)
                .timestamp(now)
                .status(AuditRecordStatus.ARCHIVED) // Using a different enum value
                .build();
        repository.saveAndFlush(record);

        // Act & Assert
        Page<AuditRecord> byActor = repository.findByActorId("user-789", PageRequest.of(0, 10));
        assertThat(byActor.getContent()).hasSize(1);
        assertThat(byActor.getContent().get(0).getResourceId()).isEqualTo("doc-001");
        assertThat(byActor.getContent().get(0).getStatus()).isEqualTo(AuditRecordStatus.ARCHIVED);

        Page<AuditRecord> byResource = repository.findByResourceTypeAndResourceId("Document", "doc-001", PageRequest.of(0, 10));
        assertThat(byResource.getContent()).hasSize(1);
    }
}
