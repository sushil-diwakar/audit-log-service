package com.example.auditlog.service;

import com.example.auditlog.dto.AuditEventRequest;
import com.example.auditlog.dto.VerificationResponse;
import com.example.auditlog.entity.AuditRecord;
import com.example.auditlog.entity.AuditRecordStatus;
import com.example.auditlog.repository.AuditRecordRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@TestPropertySource(properties = "spring.jpa.hibernate.ddl-auto=create-drop")
public class RetentionIntegrationTest {

    @Autowired
    private RetentionService retentionService;

    @Autowired
    private AuditService auditService;

    @Autowired
    private ChainVerificationService verificationService;

    @Autowired
    private AuditRecordRepository auditRecordRepository;

    @Autowired
    private ObjectMapper objectMapper;

    @BeforeEach
    void setUp() {
        auditRecordRepository.deleteAll();
    }

    @Test
    void testRetentionSoftArchivalAndChainIntegrity() throws Exception {
        Instant t1 = Instant.parse("2024-01-01T10:00:00Z");
        Instant t2 = Instant.parse("2024-01-02T10:00:00Z");
        Instant t3 = Instant.parse("2024-01-03T10:00:00Z");

        AuditEventRequest req1 = new AuditEventRequest();
        req1.setActorId("user1"); req1.setEventType("LOGIN"); req1.setResourceType("USER"); req1.setResourceId("user1");
        req1.setPayload(objectMapper.readTree("{\"ip\":\"10.0.0.1\"}")); req1.setTimestamp(t1);
        auditService.createAuditEvent(req1);

        AuditEventRequest req2 = new AuditEventRequest();
        req2.setActorId("user1"); req2.setEventType("UPDATE"); req2.setResourceType("PROFILE"); req2.setResourceId("prof1");
        req2.setPayload(objectMapper.readTree("{\"field\":\"email\"}")); req2.setTimestamp(t2);
        auditService.createAuditEvent(req2);

        AuditEventRequest req3 = new AuditEventRequest();
        req3.setActorId("user1"); req3.setEventType("LOGOUT"); req3.setResourceType("USER"); req3.setResourceId("user1");
        req3.setPayload(objectMapper.readTree("{\"duration\":3600}")); req3.setTimestamp(t3);
        auditService.createAuditEvent(req3);

        List<AuditRecord> initialRecords = auditRecordRepository.findAll();
        assertThat(initialRecords).hasSize(3);
        assertThat(initialRecords).extracting(AuditRecord::getStatus).containsOnly(AuditRecordStatus.ACTIVE);

        // Verify chain is valid initially
        VerificationResponse initialVerification = verificationService.verifyChain();
        assertThat(initialVerification.isValid()).isTrue();

        AuditRecord initialRecord1 = initialRecords.stream().filter(r -> r.getTimestamp().equals(t1)).findFirst().orElseThrow();
        String expPreviousHash = initialRecord1.getPreviousHash();
        String expRecordHash = initialRecord1.getRecordHash();
        String expEventType = initialRecord1.getEventType();
        String expActorId = initialRecord1.getActorId();
        String expResourceType = initialRecord1.getResourceType();
        String expResourceId = initialRecord1.getResourceId();
        String expPayload = initialRecord1.getPayload().toString();
        
        // 2. Perform archival for records before t2 (should archive only the first one)
        var response = retentionService.archiveRecordsBefore(t2);
        
        // Test 1: Expected records archived
        assertThat(response.getArchivedCount()).isEqualTo(1);
        
        List<AuditRecord> afterFirstArchival = auditRecordRepository.findAll();
        AuditRecord record1 = afterFirstArchival.stream().filter(r -> r.getTimestamp().equals(t1)).findFirst().orElseThrow();
        AuditRecord record2 = afterFirstArchival.stream().filter(r -> r.getTimestamp().equals(t2)).findFirst().orElseThrow();
        AuditRecord record3 = afterFirstArchival.stream().filter(r -> r.getTimestamp().equals(t3)).findFirst().orElseThrow();
        
        assertThat(record1.getStatus()).isEqualTo(AuditRecordStatus.ARCHIVED);
        
        // Test 2: Newer records remain active
        assertThat(record2.getStatus()).isEqualTo(AuditRecordStatus.ACTIVE);
        assertThat(record3.getStatus()).isEqualTo(AuditRecordStatus.ACTIVE);

        // Test 3: Idempotent
        var response2 = retentionService.archiveRecordsBefore(t2);
        assertThat(response2.getArchivedCount()).isEqualTo(0);

        // Test 5: Prove archived records retain hashes and data
        assertThat(record1.getPreviousHash()).isEqualTo(expPreviousHash);
        assertThat(record1.getRecordHash()).isEqualTo(expRecordHash);
        assertThat(record1.getEventType()).isEqualTo(expEventType);
        assertThat(record1.getActorId()).isEqualTo(expActorId);
        assertThat(record1.getResourceType()).isEqualTo(expResourceType);
        assertThat(record1.getResourceId()).isEqualTo(expResourceId);
        assertThat(record1.getPayload().toString()).isEqualTo(expPayload);
        
        // Test 4: Verification stays valid after archival
        VerificationResponse afterArchivalVerification = verificationService.verifyChain();
        assertThat(afterArchivalVerification.isValid()).isTrue();
        
        // Archive one more
        var response3 = retentionService.archiveRecordsBefore(t3);
        assertThat(response3.getArchivedCount()).isEqualTo(1);
        VerificationResponse finalVerification = verificationService.verifyChain();
        assertThat(finalVerification.isValid()).isTrue();
    }
}
