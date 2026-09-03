package com.example.auditlog.service;

import com.example.auditlog.dto.AuditEventRequest;
import com.example.auditlog.dto.AuditEventResponse;
import com.example.auditlog.dto.ExportBundle;
import com.example.auditlog.dto.ExportRecord;
import com.example.auditlog.dto.RedactionRequest;
import com.example.auditlog.entity.AuditRecordStatus;
import com.example.auditlog.repository.AuditRecordRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MvcResult;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@ActiveProfiles("dev")
@WithMockUser(authorities = {"SCOPE_audit:read", "SCOPE_audit:write", "SCOPE_audit:redact", "SCOPE_audit:archive", "SCOPE_audit:export", "SCOPE_audit:verify"})
@AutoConfigureMockMvc
class ExportIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private AuditService auditService;

    @Autowired
    private RedactionService redactionService;

    @Autowired
    private RetentionService retentionService;

    @Autowired
    private AuditRecordRepository auditRecordRepository;

    @Autowired
    private HashService hashService;

    @Autowired
    private ObjectMapper objectMapper;

    @BeforeEach
    void setUp() {
        auditRecordRepository.deleteAllInBatch();
    }

    @Test
    void testExportValidationFailure() throws Exception {
        // Missing both actorId and resourceId -> 400 Bad Request
        mockMvc.perform(get("/audit/export"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void testExportByActorIdAndOfflineVerification() throws Exception {
        // Create mixed records
        createRecord("userA", "RES1", "{\"data\":\"A1\"}");
        AuditEventResponse r2 = createRecord("userB", "RES2", "{\"data\":\"B1\"}");
        createRecord("userA", "RES3", "{\"data\":\"A2\"}");
        AuditEventResponse r4 = createRecord("userB", "RES4", "{\"data\":\"B2\"}");
        createRecord("userA", "RES5", "{\"data\":\"A3\"}");

        // Redact r2
        redactionService.redactRecord(r2.getId(), new RedactionRequest(List.of("/data")));

        // Archive r4 (use a cutoff in the future to ensure it gets archived)
        retentionService.archiveRecordsBefore(Instant.now().plusSeconds(3600));

        // Export for userB (this will include one REDACTED and one ARCHIVED record)
        MvcResult result = mockMvc.perform(get("/audit/export?actorId=userB"))
                .andExpect(status().isOk())
                .andReturn();

        String jsonResponse = result.getResponse().getContentAsString();
        ExportBundle bundle = objectMapper.readValue(jsonResponse, ExportBundle.class);

        // Assert Metadata
        assertNotNull(bundle.getMetadata());
        assertEquals("userB", bundle.getMetadata().getQuery().getActorId());
        assertNull(bundle.getMetadata().getQuery().getResourceId());
        assertEquals(2, bundle.getMetadata().getRecordCount());
        
        List<ExportRecord> records = bundle.getRecords();
        assertEquals(2, records.size());

        ExportRecord exportedR2 = records.get(0);
        ExportRecord exportedR4 = records.get(1);

        // Assert boundary metadata matches
        assertEquals(exportedR2.getPreviousHash(), bundle.getMetadata().getFirstExportedRecordPreviousHash());
        assertEquals(exportedR2.getRecordHash(), bundle.getMetadata().getFirstExportedRecordHash());
        assertEquals(exportedR4.getRecordHash(), bundle.getMetadata().getLastExportedRecordHash());

        // Sparse chain proof: r3 is omitted from the filtered export, so r4.previousHash points to the omitted r3 record.
        // Therefore, exportedR2.getRecordHash() is NOT equal to exportedR4.getPreviousHash().
        assertNotEquals(exportedR2.getRecordHash(), exportedR4.getPreviousHash());

        // Offline Verification of the bundle
        for (ExportRecord record : records) {
            String expectedContentHash;
            if (record.getStatus() == AuditRecordStatus.REDACTED) {
                // For redacted, we just trust the original contentHash provided
                expectedContentHash = record.getContentHash();
                assertTrue(record.getPayload().has("data"));
                assertTrue(record.getPayload().get("data").has("redacted"));
            } else {
                // For ACTIVE/ARCHIVED, we must be able to independently recalculate the contentHash
                expectedContentHash = hashService.calculateContentHash(
                        com.example.auditlog.entity.AuditRecord.builder()
                                .eventType(record.getEventType())
                                .actorId(record.getActorId())
                                .resourceType(record.getResourceType())
                                .resourceId(record.getResourceId())
                                .payload(record.getPayload())
                                .timestamp(record.getTimestamp())
                                .build()
                );
                assertEquals(expectedContentHash, record.getContentHash());
            }

            // We must always be able to independently recalculate the recordHash
            String expectedRecordHash = hashService.calculateRecordHash(expectedContentHash, record.getPreviousHash());
            assertEquals(expectedRecordHash, record.getRecordHash());
        }
        
        // Assert Archive/Redacted statuses
        assertEquals(AuditRecordStatus.REDACTED, exportedR2.getStatus());
        assertEquals(AuditRecordStatus.ARCHIVED, exportedR4.getStatus());
    }

    @Test
    void testExportByResourceId() throws Exception {
        createRecord("userA", "RES1", "{\"data\":\"1\"}");
        createRecord("userB", "RES1", "{\"data\":\"2\"}");
        
        MvcResult result = mockMvc.perform(get("/audit/export?resourceId=RES1"))
                .andExpect(status().isOk())
                .andReturn();

        ExportBundle bundle = objectMapper.readValue(result.getResponse().getContentAsString(), ExportBundle.class);
        assertEquals(2, bundle.getMetadata().getRecordCount());
        assertEquals("RES1", bundle.getMetadata().getQuery().getResourceId());
    }

    private AuditEventResponse createRecord(String actorId, String resourceId, String payloadJson) throws Exception {
        AuditEventRequest req = new AuditEventRequest();
        req.setActorId(actorId);
        req.setEventType("TEST_EVENT");
        req.setResourceType("TEST_RES");
        req.setResourceId(resourceId);
        req.setPayload(objectMapper.readTree(payloadJson));
        req.setTimestamp(Instant.now().truncatedTo(java.time.temporal.ChronoUnit.MILLIS));
        return auditService.createAuditEvent(req);
    }
}
