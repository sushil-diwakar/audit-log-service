package com.example.auditlog.service;

import com.example.auditlog.dto.AuditEventRequest;
import com.example.auditlog.dto.AuditEventResponse;
import com.example.auditlog.dto.RedactionRequest;
import com.example.auditlog.dto.RedactionResponse;
import com.example.auditlog.dto.VerificationResponse;
import com.example.auditlog.entity.AuditRecord;
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
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@ActiveProfiles("dev")
@WithMockUser(authorities = {"SCOPE_audit:read", "SCOPE_audit:write", "SCOPE_audit:redact", "SCOPE_audit:archive", "SCOPE_audit:export", "SCOPE_audit:verify"})
@AutoConfigureMockMvc
@TestPropertySource(properties = "spring.jpa.hibernate.ddl-auto=create-drop")
public class RedactionIntegrationTest {

    @Autowired
    private AuditService auditService;

    @Autowired
    private RedactionService redactionService;

    @Autowired
    private ChainVerificationService verificationService;

    @Autowired
    private AuditRecordRepository repository;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        repository.deleteAll();
    }

    @Test
    void testStructuredRedactionAndChainPreservation() throws Exception {
        // 1. Create a record with nested payload
        AuditEventRequest req = new AuditEventRequest();
        req.setActorId("admin");
        req.setEventType("USER_UPDATE");
        req.setResourceType("USER");
        req.setResourceId("user123");
        req.setPayload(objectMapper.readTree(
            "{\"email\":\"secret@test.com\",\"nested\":{\"ssn\":\"123-45-6789\",\"age\":30},\"tags\":[\"a\",\"b\"]}"
        ));
        
        AuditEventResponse created = auditService.createAuditEvent(req);
        UUID id = created.getId();
        
        AuditRecord originalRecord = repository.findById(id).orElseThrow();
        String originalContentHash = originalRecord.getContentHash();
        String originalRecordHash = originalRecord.getRecordHash();
        String originalPreviousHash = originalRecord.getPreviousHash();
        
        assertThat(originalContentHash).isNotNull();
        assertThat(verificationService.verifyChain().isValid()).isTrue();

        // 2. Redact specific fields
        RedactionRequest redactReq = new RedactionRequest(List.of("/email", "/nested/ssn"));
        RedactionResponse response = redactionService.redactRecord(id, redactReq);
        
        assertThat(response.getStatus()).isEqualTo(AuditRecordStatus.REDACTED);

        // 3. Verify the payload was structured-redacted correctly
        AuditRecord redactedRecord = repository.findById(id).orElseThrow();
        assertThat(redactedRecord.getStatus()).isEqualTo(AuditRecordStatus.REDACTED);
        
        // Assert cryptographic fields are strictly unchanged
        assertThat(redactedRecord.getContentHash()).isEqualTo(originalContentHash);
        assertThat(redactedRecord.getRecordHash()).isEqualTo(originalRecordHash);
        assertThat(redactedRecord.getPreviousHash()).isEqualTo(originalPreviousHash);
        
        // Assert event metadata unchanged
        assertThat(redactedRecord.getActorId()).isEqualTo("admin");
        assertThat(redactedRecord.getEventType()).isEqualTo("USER_UPDATE");
        
        // Assert payload redaction structure - explicit check for multiple fields
        String payloadJson = redactedRecord.getPayload().toString();
        assertThat(payloadJson).contains("\"redacted\":true");
        assertThat(payloadJson).doesNotContain("secret@test.com");
        assertThat(payloadJson).doesNotContain("123-45-6789");
        assertThat(payloadJson).contains("\"age\":30"); // Unrelated fields remain
        assertThat(payloadJson).contains("\"tags\":[\"a\",\"b\"]"); // Arrays remain

        // 4. Verification must remain valid (treating REDACTED records securely)
        VerificationResponse verificationAfter = verificationService.verifyChain();
        assertThat(verificationAfter.isValid()).isTrue();

        // 5. Already redacted should fail
        assertThatThrownBy(() -> redactionService.redactRecord(id, redactReq))
            .isInstanceOf(ResponseStatusException.class)
            .hasMessageContaining("already redacted");
    }

    @Test
    void testArrayElementRedaction() throws Exception {
        AuditEventRequest req = new AuditEventRequest();
        req.setActorId("admin");
        req.setEventType("BILLING");
        req.setResourceType("USER");
        req.setResourceId("user123");
        req.setPayload(objectMapper.readTree(
            "{\"cards\":[{\"number\":\"111\"},{\"number\":\"222\"}]}"
        ));
        AuditEventResponse created = auditService.createAuditEvent(req);
        UUID id = created.getId();

        redactionService.redactRecord(id, new RedactionRequest(List.of("/cards/0/number")));

        AuditRecord redactedRecord = repository.findById(id).orElseThrow();
        String payloadJson = redactedRecord.getPayload().toString();
        
        // Target is removed, unrelated array elements remain
        assertThat(payloadJson).contains("\"redacted\":true");
        assertThat(payloadJson).doesNotContain("\"111\"");
        assertThat(payloadJson).contains("\"222\"");
        
        assertThat(verificationService.verifyChain().isValid()).isTrue();
    }

    @Test
    void testInvalidJsonPointerSyntax() throws Exception {
        AuditEventRequest req = new AuditEventRequest();
        req.setActorId("admin");
        req.setEventType("LOGIN");
        req.setResourceType("USER");
        req.setResourceId("user123");
        req.setPayload(objectMapper.readTree("{\"key\":\"val\"}"));
        AuditEventResponse created = auditService.createAuditEvent(req);
        UUID id = created.getId();

        AuditRecord originalRecord = repository.findById(id).orElseThrow();

        assertThatThrownBy(() -> redactionService.redactRecord(id, new RedactionRequest(List.of("not/a/pointer"))))
            .isInstanceOf(ResponseStatusException.class)
            .hasMessageContaining("Invalid JSON Pointer");

        // Verify no changes were made
        AuditRecord untouchedRecord = repository.findById(id).orElseThrow();
        assertThat(untouchedRecord.getStatus()).isEqualTo(AuditRecordStatus.ACTIVE);
        assertThat(untouchedRecord.getPayload().toString()).isEqualTo(originalRecord.getPayload().toString());
    }

    @Test
    void testMissingPathAtomicity() throws Exception {
        AuditEventRequest req = new AuditEventRequest();
        req.setActorId("admin");
        req.setEventType("LOGIN");
        req.setResourceType("USER");
        req.setResourceId("user123");
        req.setPayload(objectMapper.readTree("{\"email\":\"secret@test.com\"}"));
        AuditEventResponse created = auditService.createAuditEvent(req);
        UUID id = created.getId();

        AuditRecord originalRecord = repository.findById(id).orElseThrow();

        // Pass one valid path and one missing path
        assertThatThrownBy(() -> redactionService.redactRecord(id, new RedactionRequest(List.of("/email", "/does-not-exist"))))
            .isInstanceOf(ResponseStatusException.class)
            .hasMessageContaining("Path not found");

        // Verify atomicity - email was not redacted
        AuditRecord untouchedRecord = repository.findById(id).orElseThrow();
        assertThat(untouchedRecord.getStatus()).isEqualTo(AuditRecordStatus.ACTIVE);
        assertThat(untouchedRecord.getPayload().toString()).contains("secret@test.com");
        assertThat(untouchedRecord.getContentHash()).isEqualTo(originalRecord.getContentHash());
        assertThat(untouchedRecord.getRecordHash()).isEqualTo(originalRecord.getRecordHash());
    }

    @Test
    void testApiLevelRedaction() throws Exception {
        AuditEventRequest req = new AuditEventRequest();
        req.setActorId("admin");
        req.setEventType("API_TEST");
        req.setResourceType("USER");
        req.setResourceId("user123");
        req.setPayload(objectMapper.readTree("{\"email\":\"api@test.com\",\"phone\":\"1234\"}"));
        AuditEventResponse created = auditService.createAuditEvent(req);
        UUID id = created.getId();

        // Valid Redaction
        String jsonRequest = "{\"paths\": [\"/email\"]}";
        mockMvc.perform(post("/audit/events/" + id + "/redact")
                .contentType(MediaType.APPLICATION_JSON)
                .content(jsonRequest))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.recordId").value(id.toString()))
                .andExpect(jsonPath("$.status").value("REDACTED"))
                .andExpect(jsonPath("$.redactedPaths[0]").value("/email"));

        // Invalid Redaction via API
        String invalidRequest = "{\"paths\": [\"/missing-path\"]}";
        mockMvc.perform(post("/audit/events/" + id + "/redact")
                .contentType(MediaType.APPLICATION_JSON)
                .content(invalidRequest))
                .andExpect(status().isBadRequest());
    }
}
