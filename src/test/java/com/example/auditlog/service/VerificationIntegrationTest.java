package com.example.auditlog.service;

import com.example.auditlog.dto.AuditEventRequest;
import com.example.auditlog.dto.AuditEventResponse;
import com.example.auditlog.dto.VerificationResponse;
import com.example.auditlog.entity.AuditRecord;
import com.example.auditlog.enums.ChainViolationType;
import com.example.auditlog.repository.AuditRecordRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.TestPropertySource;

import java.time.Instant;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@ActiveProfiles("dev")
@TestPropertySource(properties = "spring.jpa.hibernate.ddl-auto=create-drop")
class VerificationIntegrationTest {

    @Autowired
    private ChainVerificationService verificationService;

    @Autowired
    private AuditService auditService;

    @Autowired
    private AuditRecordRepository repository;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Autowired
    private ObjectMapper mapper;

    @BeforeEach
    void setUp() {
        repository.deleteAll();
    }

    private AuditEventRequest createRequest(String actor) throws Exception {
        AuditEventRequest req = new AuditEventRequest();
        req.setEventType("TEST_EVENT");
        req.setActorId(actor);
        req.setResourceType("SYS");
        req.setResourceId("1");
        req.setPayload(mapper.readTree("{\"action\":\"test\"}"));
        req.setTimestamp(Instant.now().truncatedTo(java.time.temporal.ChronoUnit.MILLIS));
        return req;
    }

    @Test
    void testEmptyDatabaseVerification() {
        VerificationResponse response = verificationService.verifyChain();
        assertThat(response.isValid()).isTrue();
        assertThat(response.getCheckedRecords()).isEqualTo(0);
    }

    @Test
    void testOneValidRecordVerification() throws Exception {
        auditService.createAuditEvent(createRequest("actor-1"));
        VerificationResponse response = verificationService.verifyChain();
        
        assertThat(response.isValid()).isTrue();
        assertThat(response.getCheckedRecords()).isEqualTo(1);
    }

    @Test
    void testMultipleValidRecordsVerification() throws Exception {
        auditService.createAuditEvent(createRequest("actor-1"));
        auditService.createAuditEvent(createRequest("actor-2"));
        auditService.createAuditEvent(createRequest("actor-3"));
        
        VerificationResponse response = verificationService.verifyChain();
        
        assertThat(response.isValid()).isTrue();
        assertThat(response.getCheckedRecords()).isEqualTo(3);
    }

    @Test
    void testTamperContent_DetectsContentHashMismatch() throws Exception {
        AuditEventResponse evt = auditService.createAuditEvent(createRequest("actor-1"));
        
        // Pass the UUID object directly so JdbcTemplate maps it correctly to BINARY(16) if needed
        int rows = jdbcTemplate.update("UPDATE audit_records SET actor_id = 'hacker' WHERE actor_id = 'actor-1'");
        assertThat(rows).isEqualTo(1);
        
        VerificationResponse response = verificationService.verifyChain();
        
        assertThat(response.isValid()).isFalse();
        assertThat(response.getViolationType()).isEqualTo(ChainViolationType.CONTENT_HASH_MISMATCH);
    }

    @Test
    void testTamperPreviousHash_DetectsBrokenLinkageOrMultipleGenesis() throws Exception {
        AuditEventResponse evt1 = auditService.createAuditEvent(createRequest("actor-1"));
        AuditEventResponse evt2 = auditService.createAuditEvent(createRequest("actor-2"));
        
        // Break the linkage by changing evt2's previousHash to a garbage value
        int rows = jdbcTemplate.update("UPDATE audit_records SET previous_hash = 'GARBAGE_LINK' WHERE actor_id = 'actor-2'");
        assertThat(rows).isEqualTo(1);
        
        VerificationResponse response = verificationService.verifyChain();
        
        assertThat(response.isValid()).isFalse();
        // Since previousHash is used in recordHash calculation, it will trigger RECORD_HASH_MISMATCH first during content integrity check
        assertThat(response.getViolationType()).isEqualTo(ChainViolationType.RECORD_HASH_MISMATCH);
    }

    @Test
    void testTamperRecordHash_DetectsRecordHashMismatch() throws Exception {
        AuditEventResponse evt = auditService.createAuditEvent(createRequest("actor-1"));
        
        int rows = jdbcTemplate.update("UPDATE audit_records SET record_hash = 'tampered' WHERE actor_id = 'actor-1'");
        assertThat(rows).isEqualTo(1);
        
        VerificationResponse response = verificationService.verifyChain();
        
        assertThat(response.isValid()).isFalse();
        assertThat(response.getViolationType()).isEqualTo(ChainViolationType.RECORD_HASH_MISMATCH);
    }

    @Autowired
    private HashService hashService;

    @Test
    void testDisconnectedOrphanRecord() throws Exception {
        // Create a normal chain
        auditService.createAuditEvent(createRequest("actor-1"));
        auditService.createAuditEvent(createRequest("actor-2"));
        
        // Manually build an orphan record
        AuditRecord orphan = AuditRecord.builder()
                .eventType("TEST_EVENT")
                .actorId("orphan-actor")
                .resourceType("SYS")
                .resourceId("1")
                .payload(mapper.readTree("{\"action\":\"test\"}"))
                .timestamp(Instant.now().truncatedTo(java.time.temporal.ChronoUnit.MILLIS))
                .build();
        
        orphan.setPreviousHash("SOME_RANDOM_UNLINKED_HASH");
        
        // Calculate exact correct hashes so it passes the RECORD_HASH_MISMATCH check
        String contentHash = hashService.calculateContentHash(orphan);
        orphan.setContentHash(contentHash);
        
        String recordHash = hashService.calculateRecordHash(contentHash, orphan.getPreviousHash());
        orphan.setRecordHash(recordHash);
        
        // Save using repository
        repository.saveAndFlush(orphan);
        
        VerificationResponse response = verificationService.verifyChain();
        
        // The chain will traverse GENESIS -> actor-1 -> actor-2.
        // It will stop.
        // Then it will see the orphan wasn't visited.
        assertThat(response.isValid()).isFalse();
        assertThat(response.getViolationType()).isEqualTo(ChainViolationType.DISCONNECTED_RECORD);
    }
}
