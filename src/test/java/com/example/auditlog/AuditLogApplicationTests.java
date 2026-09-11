package com.example.auditlog;

import com.example.auditlog.entity.AuditRecord;
import com.example.auditlog.entity.AuditRecordStatus;
import com.example.auditlog.repository.AuditRecordRepository;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.SQLException;
import java.time.Instant;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SpringBootTest(properties = {
    "DEV_USER=test", "DEV_PASSWORD=test", 
    "spring.datasource.url=jdbc:h2:mem:auditdb;DB_CLOSE_DELAY=-1", 
    "spring.datasource.username=sa", "spring.datasource.driver-class-name=org.h2.Driver", "spring.datasource.password="
})
@ActiveProfiles("dev")
class AuditLogApplicationTests {

    @org.springframework.test.context.DynamicPropertySource
    static void dynamicProperties(org.springframework.test.context.DynamicPropertyRegistry registry) throws Exception {
        java.security.KeyPairGenerator generator = java.security.KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        java.security.KeyPair pair = generator.generateKeyPair();
        registry.add("audit.signature.public-key", () -> java.util.Base64.getEncoder().encodeToString(pair.getPublic().getEncoded()));
        registry.add("audit.signature.private-key", () -> java.util.Base64.getEncoder().encodeToString(pair.getPrivate().getEncoded()));
        registry.add("audit.signature.key-id", () -> "test-key-dynamic");
        registry.add("audit.redaction.hmac-secret", () -> java.util.UUID.randomUUID().toString());
    }

    @Autowired
    private DataSource dataSource;

    @Autowired
    private AuditRecordRepository auditRecordRepository;

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    void contextLoads() {
        // Verifies that Spring Boot application context loads successfully
    }

    @Test
    void testDatabaseConnection() throws SQLException {
        assertNotNull(dataSource, "DataSource bean should be configured and injected");
        try (Connection connection = dataSource.getConnection()) {
            assertNotNull(connection, "Database connection should not be null");
            assertTrue(connection.isValid(2), "Database connection should be valid");
        }
    }

    @Test
    void testAuditRecordPersistence() throws Exception {
        // 2. Creates an AuditRecord
        JsonNode payload = objectMapper.readTree("{\"ip\":\"127.0.0.1\",\"success\":true}");
        
        AuditRecord record = AuditRecord.builder()
                .eventType("ACCOUNT_LOGIN")
                .actorId("user-123")
                .resourceType("ACCOUNT")
                .resourceId("account-456")
                .payload(payload)
                .timestamp(Instant.now())
                .status(AuditRecordStatus.ACTIVE)
                .contentHash("testhash")
                .build();

        // 3. Saves the record using AuditRecordRepository
        AuditRecord savedRecord = auditRecordRepository.save(record);

        // 4. Retrieves it using findById()
        Optional<AuditRecord> retrievedOptional = auditRecordRepository.findById(savedRecord.getId());
        
        // 5. Asserts that the record exists and fields match
        assertThat(retrievedOptional).isPresent();
        
        AuditRecord retrieved = retrievedOptional.get();
        assertThat(retrieved.getEventType()).isEqualTo("ACCOUNT_LOGIN");
        assertThat(retrieved.getActorId()).isEqualTo("user-123");
        assertThat(retrieved.getResourceType()).isEqualTo("ACCOUNT");
        assertThat(retrieved.getResourceId()).isEqualTo("account-456");
        
        // Payload matches
        assertThat(retrieved.getPayload()).isNotNull();
        assertThat(retrieved.getPayload().get("ip").asText()).isEqualTo("127.0.0.1");
        assertThat(retrieved.getPayload().get("success").asBoolean()).isTrue();
        
        // Status and createdAt
        assertThat(retrieved.getStatus()).isEqualTo(AuditRecordStatus.ACTIVE);
        assertThat(retrieved.getCreatedAt()).isNotNull();
    }
}
