package com.example.auditlog.exception;

import com.example.auditlog.entity.AuditRecord;
import com.example.auditlog.repository.AuditRecordRepository;
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
import org.springframework.jdbc.core.JdbcTemplate;

import java.util.UUID;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@ActiveProfiles("dev")
@WithMockUser
@AutoConfigureMockMvc
@TestPropertySource(properties = "spring.jpa.hibernate.ddl-auto=create-drop")
public class GlobalExceptionHandlerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Autowired
    private AuditRecordRepository repository;

    @BeforeEach
    void setUp() {
        jdbcTemplate.execute("DELETE FROM audit_records");
    }

    @Test
    void testInvalidRequestBody_Returns400Json() throws Exception {
        // Missing required fields
        String invalidJson = """
            {
                "eventType": "LOGIN"
            }
        """;
        mockMvc.perform(post("/audit/events")
                .contentType(MediaType.APPLICATION_JSON)
                .content(invalidJson))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400))
                .andExpect(jsonPath("$.error").value("Bad Request"))
                .andExpect(jsonPath("$.message").exists());
    }

    @Test
    void testMissingExportFilters_Returns400Json() throws Exception {
        mockMvc.perform(get("/audit/export"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400))
                .andExpect(jsonPath("$.error").value("Bad Request"))
                .andExpect(jsonPath("$.message").value("At least one of actorId or resourceId must be provided"));
    }

    @Test
    void testInvalidJsonPointer_Returns400Json() throws Exception {
        AuditRecord record = new AuditRecord();
        record.setEventType("TEST");
        record.setActorId("actor");
        record.setResourceType("RES");
        record.setResourceId("123");
        record.setTimestamp(java.time.Instant.now());
        record.setContentHash("1111111111111111111111111111111111111111111111111111111111111111");
        record.setRecordHash("2222222222222222222222222222222222222222222222222222222222222222");
        
        com.fasterxml.jackson.databind.ObjectMapper mapper = new com.fasterxml.jackson.databind.ObjectMapper();
        record.setPayload(mapper.createObjectNode().put("test", "value"));
        record = repository.saveAndFlush(record);

        String redactJson = """
            {
                "paths": ["invalid-pointer-no-slash"]
            }
        """;
        mockMvc.perform(post("/audit/events/" + record.getId() + "/redact")
                .contentType(MediaType.APPLICATION_JSON)
                .content(redactJson))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400))
                .andExpect(jsonPath("$.error").value("Bad Request"))
                .andExpect(jsonPath("$.message").value("Invalid JSON Pointer: invalid-pointer-no-slash"));
    }

    @Test
    void testMissingAuditRecordForRedaction_Returns404Json() throws Exception {
        String redactJson = """
            {
                "paths": ["/test"]
            }
        """;
        mockMvc.perform(post("/audit/events/" + UUID.randomUUID() + "/redact")
                .contentType(MediaType.APPLICATION_JSON)
                .content(redactJson))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.status").value(404))
                .andExpect(jsonPath("$.error").value("Not Found"))
                .andExpect(jsonPath("$.message").value("Audit record not found"));
    }

    @Test
    void testInvalidPaginationType_Returns400Json() throws Exception {
        mockMvc.perform(get("/audit/events").param("page", "abc"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400))
                .andExpect(jsonPath("$.error").value("Bad Request"))
                .andExpect(jsonPath("$.message").value("Parameter 'page' should be of type 'int'"));
    }
}
