package com.example.auditlog.service;

import com.example.auditlog.entity.AuditRecord;
import com.example.auditlog.entity.AuditRecordStatus;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

class HashServiceTest {

    private HashService hashService;
    private ObjectMapper mapper;

    @BeforeEach
    void setUp() {
        mapper = new ObjectMapper();
        hashService = new HashService(mapper);
    }

    private AuditRecord createBaseRecord() throws JsonProcessingException {
        return AuditRecord.builder()
                .id(UUID.randomUUID())
                .eventType("LOGIN")
                .actorId("user-1")
                .resourceType("ACCOUNT")
                .resourceId("acc-1")
                .payload(mapper.readTree("{\"ip\": \"127.0.0.1\", \"success\": true}"))
                .timestamp(Instant.parse("2024-01-01T12:00:00Z"))
                .status(AuditRecordStatus.ACTIVE)
                .previousHash("PREV_HASH")
                .recordHash("RECORD_HASH")
                .createdAt(Instant.now())
                .build();
    }

    @Test
    void testSameRecordProducesSameHash() throws Exception {
        AuditRecord record1 = createBaseRecord();
        AuditRecord record2 = createBaseRecord();

        String hash1 = hashService.calculateContentHash(record1);
        String hash2 = hashService.calculateContentHash(record2);

        assertThat(hash1).isEqualTo(hash2);
    }

    @Test
    void testFormatIs64CharLowercaseHex() throws Exception {
        AuditRecord record = createBaseRecord();
        String hash = hashService.calculateContentHash(record);

        assertThat(hash).hasSize(64);
        assertThat(hash).matches("^[a-f0-9]{64}$");
    }

    @Test
    void testChangingEventTypeChangesHash() throws Exception {
        AuditRecord record1 = createBaseRecord();
        AuditRecord record2 = createBaseRecord();
        record2.setEventType("LOGOUT");

        assertThat(hashService.calculateContentHash(record1))
                .isNotEqualTo(hashService.calculateContentHash(record2));
    }

    @Test
    void testChangingActorIdChangesHash() throws Exception {
        AuditRecord record1 = createBaseRecord();
        AuditRecord record2 = createBaseRecord();
        record2.setActorId("user-2");

        assertThat(hashService.calculateContentHash(record1))
                .isNotEqualTo(hashService.calculateContentHash(record2));
    }

    @Test
    void testChangingResourceTypeChangesHash() throws Exception {
        AuditRecord record1 = createBaseRecord();
        AuditRecord record2 = createBaseRecord();
        record2.setResourceType("SESSION");

        assertThat(hashService.calculateContentHash(record1))
                .isNotEqualTo(hashService.calculateContentHash(record2));
    }

    @Test
    void testChangingResourceIdChangesHash() throws Exception {
        AuditRecord record1 = createBaseRecord();
        AuditRecord record2 = createBaseRecord();
        record2.setResourceId("acc-2");

        assertThat(hashService.calculateContentHash(record1))
                .isNotEqualTo(hashService.calculateContentHash(record2));
    }

    @Test
    void testChangingPayloadChangesHash() throws Exception {
        AuditRecord record1 = createBaseRecord();
        AuditRecord record2 = createBaseRecord();
        record2.setPayload(mapper.readTree("{\"ip\": \"192.168.1.1\", \"success\": true}"));

        assertThat(hashService.calculateContentHash(record1))
                .isNotEqualTo(hashService.calculateContentHash(record2));
    }

    @Test
    void testChangingTimestampChangesHash() throws Exception {
        AuditRecord record1 = createBaseRecord();
        AuditRecord record2 = createBaseRecord();
        record2.setTimestamp(Instant.parse("2024-01-01T12:00:01Z"));

        assertThat(hashService.calculateContentHash(record1))
                .isNotEqualTo(hashService.calculateContentHash(record2));
    }

    @Test
    void testChangingIgnoredFieldsDoesNotChangeHash() throws Exception {
        AuditRecord record1 = createBaseRecord();
        String baseHash = hashService.calculateContentHash(record1);

        AuditRecord record2 = createBaseRecord();
        
        // Mutate ignored fields
        record2.setId(UUID.randomUUID());
        record2.setCreatedAt(Instant.parse("2099-01-01T00:00:00Z"));
        record2.setStatus(AuditRecordStatus.REDACTED);
        record2.setPreviousHash("NEW_PREV_HASH");
        record2.setRecordHash("NEW_RECORD_HASH");

        String newHash = hashService.calculateContentHash(record2);

        assertThat(newHash).isEqualTo(baseHash);
    }

    @Test
    void testJsonPayloadKeyOrderingIsDeterministic() throws Exception {
        AuditRecord record1 = createBaseRecord();
        // Keys: a, b, c
        record1.setPayload(mapper.readTree("{\"a\": 1, \"b\": 2, \"c\": 3}"));
        
        AuditRecord record2 = createBaseRecord();
        // Keys: c, a, b (same semantic content, different order)
        record2.setPayload(mapper.readTree("{\"c\": 3, \"a\": 1, \"b\": 2}"));

        String hash1 = hashService.calculateContentHash(record1);
        String hash2 = hashService.calculateContentHash(record2);

        assertThat(hash1).isEqualTo(hash2);
    }
    
    @Test
    void testNestedJsonPayloadKeyOrderingIsDeterministic() throws Exception {
        AuditRecord record1 = createBaseRecord();
        record1.setPayload(mapper.readTree("{\"root\": {\"z\": 1, \"a\": 2}}"));
        
        AuditRecord record2 = createBaseRecord();
        record2.setPayload(mapper.readTree("{\"root\": {\"a\": 2, \"z\": 1}}"));

        String hash1 = hashService.calculateContentHash(record1);
        String hash2 = hashService.calculateContentHash(record2);

        assertThat(hash1).isEqualTo(hash2);
    }
    @Test
    void testJsonArrayOrderingProducesDifferentHashes() throws Exception {
        AuditRecord record1 = createBaseRecord();
        record1.setPayload(mapper.readTree("{\"roles\":[\"admin\",\"user\"]}"));

        AuditRecord record2 = createBaseRecord();
        record2.setPayload(mapper.readTree("{\"roles\":[\"user\",\"admin\"]}"));

        String hash1 = hashService.calculateContentHash(record1);
        String hash2 = hashService.calculateContentHash(record2);

        // Arrays are ordered, changing their order should result in different hashes
        assertThat(hash1).isNotEqualTo(hash2);
    }
}
