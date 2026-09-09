package com.example.auditlog;

import com.example.auditlog.dto.AuditEventRequest;
import com.example.auditlog.service.HashService;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.http.MediaType;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MvcResult;

import com.example.auditlog.entity.AuditRecord;
import java.time.Instant;

import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(properties = {
    "DEV_USER=test", "DEV_PASSWORD=test", 
    "spring.datasource.url=jdbc:h2:mem:auditdb;DB_CLOSE_DELAY=-1;MODE=MySQL", 
    "spring.datasource.username=sa", "spring.datasource.driver-class-name=org.h2.Driver", "spring.datasource.password="
})
@ActiveProfiles("dev")
@WithMockUser(authorities = {"SCOPE_audit:read", "SCOPE_audit:write", "SCOPE_audit:redact", "SCOPE_audit:archive", "SCOPE_audit:export", "SCOPE_audit:verify"})
@AutoConfigureMockMvc
@TestPropertySource(properties = "spring.jpa.hibernate.ddl-auto=create-drop")
public class ScenarioCEndToEndTest {

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
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private HashService hashService;

    @Autowired
    private org.springframework.jdbc.core.JdbcTemplate jdbcTemplate;

    @org.junit.jupiter.api.BeforeEach
    void setUp() {
        jdbcTemplate.execute("DELETE FROM audit_records");
    }

    @Test
    public void testScenarioCEndToEnd_RegulatorAccessAudit() throws Exception {
        // 1. Simulate an upstream system/CSR recording an ACCOUNT_READ event for a CLIENT_ACCOUNT
        String csrActorId = "csr-agent-774";
        String clientAccountId = UUID.randomUUID().toString();
        
        AuditEventRequest request = new AuditEventRequest();
        request.setEventType("ACCOUNT_READ");
        request.setActorId(csrActorId);
        request.setResourceType("CLIENT_ACCOUNT");
        request.setResourceId(clientAccountId);
        
        // Include useful structured metadata in payload
        JsonNode payload = objectMapper.valueToTree(Map.of(
                "ipAddress", "192.168.1.5",
                "fieldsViewed", new String[]{"balance", "transactionHistory"},
                "justification", "Customer called support line"
        ));
        request.setPayload(payload);

        // POST the event
        MvcResult postResult = mockMvc.perform(post("/audit/events")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.id").exists())
                .andReturn();

        JsonNode postResponse = objectMapper.readTree(postResult.getResponse().getContentAsString());
        String eventId = postResponse.get("id").asText();

        // 2. Query GET /audit/events using resourceType=CLIENT_ACCOUNT and resourceId=<id>
        mockMvc.perform(get("/audit/events")
                .param("resourceType", "CLIENT_ACCOUNT")
                .param("resourceId", clientAccountId))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content[0].id").value(eventId))
                .andExpect(jsonPath("$.content[0].eventType").value("ACCOUNT_READ"))
                .andExpect(jsonPath("$.content[0].actorId").value(csrActorId))
                .andExpect(jsonPath("$.content[0].resourceId").value(clientAccountId))
                // Verify payload context metadata
                .andExpect(jsonPath("$.content[0].payload.ipAddress").value("192.168.1.5"));

        // 3. Export the same resource using GET /audit/export?resourceId=<id>
        MvcResult exportResult = mockMvc.perform(get("/audit/export")
                .param("resourceId", clientAccountId))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.metadata").exists())
                .andExpect(jsonPath("$.records").isArray())
                .andReturn();

        JsonNode exportResponse = objectMapper.readTree(exportResult.getResponse().getContentAsString());
        
        // Verify the export contains the event
        JsonNode records = exportResponse.get("records");
        assertTrue(records.size() >= 1, "Export should contain at least the created record");
        
        JsonNode exportedRecord = records.get(0);
        assertEquals(eventId, exportedRecord.get("id").asText());
        
        // 4. Verify the exported record's hashes can be independently recalculated using the existing HashService
        String contentHash = exportedRecord.get("contentHash").asText();
        String previousHash = exportedRecord.get("previousHash").asText();
        String providedRecordHash = exportedRecord.get("recordHash").asText();

        // 4a. Reconstruct an AuditRecord to independently calculate expected contentHash
        AuditRecord reconstructed = new AuditRecord();
        reconstructed.setEventType(exportedRecord.get("eventType").asText());
        reconstructed.setActorId(exportedRecord.get("actorId").asText());
        reconstructed.setResourceType(exportedRecord.get("resourceType").asText());
        reconstructed.setResourceId(exportedRecord.get("resourceId").asText());
        reconstructed.setPayload(exportedRecord.get("payload"));
        if (exportedRecord.hasNonNull("timestamp")) {
            reconstructed.setTimestamp(Instant.parse(exportedRecord.get("timestamp").asText()));
        }
        
        String expectedContentHash = hashService.calculateContentHash(reconstructed);
        assertEquals(expectedContentHash, contentHash, "The offline recalculated contentHash must strictly match the exported contentHash");

        // 4b. Verify the recordHash using contentHash and previousHash
        String calculatedRecordHash = hashService.calculateRecordHash(contentHash, previousHash);
        
        assertEquals(providedRecordHash, calculatedRecordHash, 
            "The offline recalculated recordHash must strictly match the exported recordHash");

        // 5. Verify GET /audit/verify remains valid
        mockMvc.perform(get("/audit/verify"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.valid").value(true));
    }
}
