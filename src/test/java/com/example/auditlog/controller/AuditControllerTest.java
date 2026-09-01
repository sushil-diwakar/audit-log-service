package com.example.auditlog.controller;

import com.example.auditlog.entity.AuditRecord;
import com.example.auditlog.repository.AuditRecordRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
class AuditControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private AuditRecordRepository repository;

    @BeforeEach
    void setUp() {
        repository.deleteAll();
    }

    @Test
    void testCreateEvent_Success_NoTimestamp() throws Exception {
        String payload = """
            {
                "eventType": "FILE_DOWNLOAD",
                "actorId": "user-444",
                "resourceType": "FILE",
                "resourceId": "file-888",
                "payload": {"fileName": "report.pdf"}
            }
        """;

        mockMvc.perform(post("/audit/events")
                .contentType(MediaType.APPLICATION_JSON)
                .content(payload))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.id").exists())
                .andExpect(jsonPath("$.eventType").value("FILE_DOWNLOAD"))
                .andExpect(jsonPath("$.actorId").value("user-444"))
                .andExpect(jsonPath("$.resourceType").value("FILE"))
                .andExpect(jsonPath("$.resourceId").value("file-888"))
                .andExpect(jsonPath("$.payload.fileName").value("report.pdf"))
                .andExpect(jsonPath("$.timestamp").exists())
                .andExpect(jsonPath("$.status").value("ACTIVE"));

        // Verify the record is persisted in AuditRecordRepository
        List<AuditRecord> records = repository.findAll();
        assertThat(records).hasSize(1);
        AuditRecord saved = records.get(0);
        assertThat(saved.getEventType()).isEqualTo("FILE_DOWNLOAD");
        assertThat(saved.getActorId()).isEqualTo("user-444");
        assertThat(saved.getResourceType()).isEqualTo("FILE");
        assertThat(saved.getResourceId()).isEqualTo("file-888");
        assertThat(saved.getPayload().get("fileName").asText()).isEqualTo("report.pdf");
        assertThat(saved.getStatus().name()).isEqualTo("ACTIVE");
    }

    @Test
    void testCreateEvent_ServerAssignedTimestamp() throws Exception {
        String payload = """
            {
                "eventType": "SYSTEM_START",
                "actorId": "system",
                "resourceType": "SYSTEM",
                "resourceId": "sys-1",
                "payload": {"status": "ok"}
            }
        """;

        mockMvc.perform(post("/audit/events")
                .contentType(MediaType.APPLICATION_JSON)
                .content(payload))
                .andExpect(status().isCreated());

        // Verify the persisted record has a non-null timestamp (server-assigned)
        List<AuditRecord> records = repository.findAll();
        assertThat(records).hasSize(1);
        assertThat(records.get(0).getTimestamp()).isNotNull();
    }

    @Test
    void testCreateEvent_CallerSuppliedTimestamp() throws Exception {
        String timestampStr = "2023-12-25T08:30:00Z";
        String payload = """
            {
                "eventType": "USER_LOGOUT",
                "actorId": "user-999",
                "resourceType": "SESSION",
                "resourceId": "sess-999",
                "payload": {"reason": "timeout"},
                "timestamp": "%s"
            }
        """.formatted(timestampStr);

        mockMvc.perform(post("/audit/events")
                .contentType(MediaType.APPLICATION_JSON)
                .content(payload))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.timestamp").value(timestampStr));

        // Verify the response/persisted record contains exactly that timestamp
        List<AuditRecord> records = repository.findAll();
        assertThat(records).hasSize(1);
        assertThat(records.get(0).getTimestamp()).isEqualTo(Instant.parse(timestampStr));
    }

    @Test
    void testCreateEvent_ValidationFailure() throws Exception {
        // Send a request missing required fields (empty object)
        String payload = "{}";

        mockMvc.perform(post("/audit/events")
                .contentType(MediaType.APPLICATION_JSON)
                .content(payload))
                .andExpect(status().isBadRequest());

        // Verify no audit record is created for the invalid request
        assertThat(repository.count()).isZero();
    }
}
