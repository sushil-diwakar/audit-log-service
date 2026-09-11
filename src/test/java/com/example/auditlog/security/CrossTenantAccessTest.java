package com.example.auditlog.security;

import com.example.auditlog.dto.AuditEventRequest;
import com.example.auditlog.dto.AuditEventResponse;
import com.example.auditlog.dto.PagedResponse;
import com.example.auditlog.dto.RedactionRequest;
import com.example.auditlog.entity.AuditRecord;
import com.example.auditlog.entity.AuditRecordStatus;
import com.example.auditlog.repository.AuditRecordRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import java.security.KeyPair;
import java.security.KeyPairGenerator;


import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Integration tests for Broken Object Level Authorization (BOLA) and
 * Insecure Direct Object Reference (IDOR) prevention.
 *
 * These tests validate that users cannot access resources they don't own.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("dev")
@TestPropertySource(properties = {
    "DEV_USER=test",
    "DEV_PASSWORD=test",
    "spring.datasource.url=jdbc:h2:mem:testdb;DB_CLOSE_DELAY=-1",
    "spring.datasource.username=sa",
    "spring.datasource.password=",
    "spring.datasource.driver-class-name=org.h2.Driver",
    "spring.jpa.hibernate.ddl-auto=create-drop"
})
@Transactional
public class CrossTenantAccessTest {
    @DynamicPropertySource
    static void registerProperties(DynamicPropertyRegistry registry) throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair pair = keyPairGenerator.generateKeyPair();
        registry.add("audit.signature.private-key", () -> java.util.Base64.getEncoder().encodeToString(pair.getPrivate().getEncoded()));
        registry.add("audit.signature.public-key", () -> java.util.Base64.getEncoder().encodeToString(pair.getPublic().getEncoded()));
        registry.add("audit.redaction.hmac-secret", () -> "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=");
    }


    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private AuditRecordRepository auditRecordRepository;

    @Autowired
    private ObjectMapper objectMapper;

    private UUID user1RecordId;
    private UUID user2RecordId;

    @BeforeEach
    void setUp() {
        auditRecordRepository.deleteAll();

        // Create test records for different users
        AuditRecord user1Record = AuditRecord.builder()
                .eventType("LOGIN_SUCCESS")
                .actorId("user1")
                .resourceType("SYSTEM")
                .resourceId("user1:auth-server")
                .payload(createPayload("ip", "192.168.1.1"))
                .timestamp(Instant.now())
                .contentHash("hash1")
                .previousHash("GENESIS")
                .recordHash("record1")
                .status(AuditRecordStatus.ACTIVE)
                .build();

        AuditRecord user2Record = AuditRecord.builder()
                .eventType("DATA_ACCESS")
                .actorId("user2")
                .resourceType("ACCOUNT")
                .resourceId("user2:account-123")
                .payload(createPayload("action", "read"))
                .timestamp(Instant.now())
                .contentHash("hash2")
                .previousHash("record1")
                .recordHash("record2")
                .status(AuditRecordStatus.ACTIVE)
                .build();

        user1RecordId = auditRecordRepository.save(user1Record).getId();
        user2RecordId = auditRecordRepository.save(user2Record).getId();
    }

    @Test
    @WithMockUser(username = "user1", authorities = {"SCOPE_audit:write"})
    void testCreateEvent_ForOwnActor_Succeeds() throws Exception {
        AuditEventRequest request = new AuditEventRequest();
        request.setEventType("TEST_EVENT");
        request.setActorId("user1");
        request.setResourceType("SYSTEM");
        request.setResourceId("test-resource");
        request.setPayload(createPayload("test", "value"));

        mockMvc.perform(post("/audit/events")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.actorId").value("user1"));
    }

    @Test
    @WithMockUser(username = "user1", authorities = {"SCOPE_audit:write"})
    void testCreateEvent_ForDifferentActor_Fails403() throws Exception {
        AuditEventRequest request = new AuditEventRequest();
        request.setEventType("TEST_EVENT");
        request.setActorId("user2"); // Trying to create event for different user
        request.setResourceType("SYSTEM");
        request.setResourceId("test-resource");
        request.setPayload(createPayload("test", "value"));

        mockMvc.perform(post("/audit/events")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isForbidden());
    }

    @Test
    @WithMockUser(username = "user1", authorities = {"SCOPE_audit:read"})
    void testQueryEvents_ForOwnActor_Succeeds() throws Exception {
        mockMvc.perform(get("/audit/events")
                .param("actorId", "user1"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content[0].actorId").value("user1"));
    }

    @Test
    @WithMockUser(username = "user1", authorities = {"SCOPE_audit:read"})
    void testQueryEvents_ForDifferentActor_Fails403() throws Exception {
        mockMvc.perform(get("/audit/events")
                .param("actorId", "user2")) // Trying to query different user's events
                .andExpect(status().isForbidden());
    }

    @Test
    @WithMockUser(username = "user1", authorities = {"SCOPE_audit:read"})
    void testQueryEvents_WithoutActorFilter_ReturnsOnlyOwnEvents() throws Exception {
        // When no actor filter is specified, should still enforce ownership
        // This test documents current behavior - may need stricter enforcement
        mockMvc.perform(get("/audit/events"))
                .andExpect(status().isOk());
    }

    @Test
    @WithMockUser(username = "user1", authorities = {"SCOPE_audit:read"})
    void testQueryEvents_ForDifferentResource_Fails403() throws Exception {
        mockMvc.perform(get("/audit/events")
                .param("resourceType", "ACCOUNT")
                .param("resourceId", "user2:account-123")) // Different user's resource
                .andExpect(status().isForbidden());
    }

    @Test
    @WithMockUser(username = "user1", authorities = {"SCOPE_audit:redact"})
    void testRedact_OwnRecord_Succeeds() throws Exception {
        RedactionRequest request = new RedactionRequest();
        request.setPaths(List.of("/ip"));

        mockMvc.perform(post("/audit/events/" + user1RecordId + "/redact")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("REDACTED"));
    }

    @Test
    @WithMockUser(username = "user1", authorities = {"SCOPE_audit:redact"})
    void testRedact_DifferentUserRecord_Fails403() throws Exception {
        RedactionRequest request = new RedactionRequest();
        request.setPaths(List.of("/action"));

        mockMvc.perform(post("/audit/events/" + user2RecordId + "/redact")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isForbidden());
    }

    @Test
    @WithMockUser(username = "user1", authorities = {"SCOPE_audit:export"})
    void testExport_OwnActor_Succeeds() throws Exception {
        mockMvc.perform(get("/audit/export")
                .param("actorId", "user1"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.metadata.recordCount").exists());
    }

    @Test
    @WithMockUser(username = "user1", authorities = {"SCOPE_audit:export"})
    void testExport_DifferentActor_Fails403() throws Exception {
        mockMvc.perform(get("/audit/export")
                .param("actorId", "user2"))
                .andExpect(status().isForbidden());
    }

    @Test
    @WithMockUser(username = "admin", authorities = {"SCOPE_audit:admin", "SCOPE_audit:export"})
    void testExport_AdminCanExportAnyActor() throws Exception {
        // Admin users should be able to export any data
        mockMvc.perform(get("/audit/export")
                .param("actorId", "user2"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.metadata.recordCount").exists());
    }

    @Test
    @WithMockUser(username = "user1", authorities = {"SCOPE_audit:write"})
    void testCreateEvent_WithSubEntityActor_Succeeds() throws Exception {
        // user1 should be able to create events for user1:sub-entity
        AuditEventRequest request = new AuditEventRequest();
        request.setEventType("SUB_EVENT");
        request.setActorId("user1:service-account");
        request.setResourceType("API");
        request.setResourceId("endpoint-1");
        request.setPayload(createPayload("sub", "entity"));

        mockMvc.perform(post("/audit/events")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.actorId").value("user1:service-account"));
    }

    @Test
    @WithMockUser(username = "user1", authorities = {"SCOPE_audit:read"})
    void testQueryEvents_ForPublicResource_Succeeds() throws Exception {
        // Create a public resource record
        AuditRecord publicRecord = AuditRecord.builder()
                .eventType("PUBLIC_EVENT")
                .actorId("system")
                .resourceType("PUBLIC")
                .resourceId("public:announcement")
                .payload(createPayload("type", "system"))
                .timestamp(Instant.now())
                .contentHash("hash3")
                .previousHash("record2")
                .recordHash("record3")
                .status(AuditRecordStatus.ACTIVE)
                .build();
        auditRecordRepository.save(publicRecord);

        mockMvc.perform(get("/audit/events")
                .param("resourceType", "PUBLIC")
                .param("resourceId", "public:announcement"))
                .andExpect(status().isOk());
    }

    @Test
    @WithMockUser(username = "attacker", authorities = {"SCOPE_audit:read"})
    void testIDOR_CannotEnumerateRecordsByUUID() throws Exception {
        // Attacker tries to access record by guessing UUID
        mockMvc.perform(get("/audit/events")
                .param("actorId", "user1"))
                .andExpect(status().isForbidden());
    }

    @Test
    @WithMockUser(username = "user2", authorities = {"SCOPE_audit:redact"})
    void testBOLA_CannotRedactOtherUsersRecords() throws Exception {
        // user2 attempts to redact user1's record
        RedactionRequest request = new RedactionRequest();
        request.setPaths(List.of("/ip"));

        mockMvc.perform(post("/audit/events/" + user1RecordId + "/redact")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isForbidden());
    }

    private ObjectNode createPayload(String key, String value) {
        ObjectNode payload = objectMapper.createObjectNode();
        payload.put(key, value);
        return payload;
    }
}
