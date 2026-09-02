package com.example.auditlog.controller;

import com.example.auditlog.entity.AuditRecord;
import com.example.auditlog.repository.AuditRecordRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.security.test.context.support.WithMockUser;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@ActiveProfiles("dev")
@WithMockUser
@AutoConfigureMockMvc
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
class AuditControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private AuditRecordRepository repository;

    private final ObjectMapper objectMapper = new ObjectMapper();

    @BeforeEach
    void setUp() {
        repository.deleteAll();
    }

    // --- POST API Tests ---

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

        List<AuditRecord> records = repository.findAll();
        assertThat(records).hasSize(1);
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

        List<AuditRecord> records = repository.findAll();
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

        List<AuditRecord> records = repository.findAll();
        assertThat(records.get(0).getTimestamp()).isEqualTo(Instant.parse(timestampStr));
    }

    @Test
    void testCreateEvent_ValidationFailure() throws Exception {
        mockMvc.perform(post("/audit/events")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{}"))
                .andExpect(status().isBadRequest());

        assertThat(repository.count()).isZero();
    }

    // --- GET API Tests ---

    private void insertTestRecords() throws Exception {
        AuditRecord r1 = AuditRecord.builder().actorId("actor-1").resourceType("USER").resourceId("usr-1").eventType("LOGIN").timestamp(Instant.parse("2024-01-01T10:00:00Z")).payload(objectMapper.readTree("{}")).contentHash("h1").build();
        AuditRecord r2 = AuditRecord.builder().actorId("actor-2").resourceType("USER").resourceId("usr-2").eventType("LOGIN").timestamp(Instant.parse("2024-01-02T10:00:00Z")).payload(objectMapper.readTree("{}")).contentHash("h2").build();
        AuditRecord r3 = AuditRecord.builder().actorId("actor-1").resourceType("DOC").resourceId("doc-1").eventType("UPLOAD").timestamp(Instant.parse("2024-01-03T10:00:00Z")).payload(objectMapper.readTree("{}")).contentHash("h3").build();
        AuditRecord r4 = AuditRecord.builder().actorId("actor-3").resourceType("DOC").resourceId("doc-2").eventType("DOWNLOAD").timestamp(Instant.parse("2024-01-04T10:00:00Z")).payload(objectMapper.readTree("{}")).contentHash("h4").build();
        AuditRecord r5 = AuditRecord.builder().actorId("actor-3").resourceType("DOC").resourceId("doc-2").eventType("DOWNLOAD").timestamp(Instant.parse("2024-01-04T10:00:00Z")).payload(objectMapper.readTree("{}")).contentHash("h5").build(); // Same timestamp for sorting test
        
        repository.saveAllAndFlush(List.of(r1, r2, r3, r4, r5));
    }

    @Test
    void testGetEvents_ByActorId() throws Exception {
        insertTestRecords();
        mockMvc.perform(get("/audit/events").param("actorId", "actor-1"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content", hasSize(2)))
                .andExpect(jsonPath("$.totalElements", is(2)));
    }

    @Test
    void testGetEvents_ByResourceTypeAndId() throws Exception {
        insertTestRecords();
        mockMvc.perform(get("/audit/events")
                .param("resourceType", "DOC")
                .param("resourceId", "doc-2"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content", hasSize(2)))
                .andExpect(jsonPath("$.totalElements", is(2)));
    }

    @Test
    void testGetEvents_ByEventType() throws Exception {
        insertTestRecords();
        mockMvc.perform(get("/audit/events").param("eventType", "LOGIN"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content", hasSize(2)))
                .andExpect(jsonPath("$.totalElements", is(2)));
    }

    @Test
    void testGetEvents_ByTimestampRange() throws Exception {
        insertTestRecords();
        mockMvc.perform(get("/audit/events")
                .param("from", "2024-01-02T00:00:00Z")
                .param("to", "2024-01-03T23:59:59Z"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content", hasSize(2)))
                .andExpect(jsonPath("$.totalElements", is(2)));
    }

    @Test
    void testGetEvents_CombinedFilters() throws Exception {
        insertTestRecords();
        mockMvc.perform(get("/audit/events")
                .param("actorId", "actor-3")
                .param("eventType", "DOWNLOAD"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content", hasSize(2)))
                .andExpect(jsonPath("$.totalElements", is(2)));
    }

    @Test
    void testGetEvents_PaginationDefaultAndStructure() throws Exception {
        insertTestRecords();
        mockMvc.perform(get("/audit/events"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content", hasSize(5)))
                .andExpect(jsonPath("$.pageNumber", is(0)))
                .andExpect(jsonPath("$.pageSize", is(20)))
                .andExpect(jsonPath("$.totalElements", is(5)))
                .andExpect(jsonPath("$.totalPages", is(1)));
    }

    @Test
    void testGetEvents_PaginationCustomSize() throws Exception {
        insertTestRecords();
        mockMvc.perform(get("/audit/events")
                .param("page", "0")
                .param("size", "2"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content", hasSize(2)))
                .andExpect(jsonPath("$.pageNumber", is(0)))
                .andExpect(jsonPath("$.pageSize", is(2)))
                .andExpect(jsonPath("$.totalElements", is(5)))
                .andExpect(jsonPath("$.totalPages", is(3)));
    }

    @Test
    void testGetEvents_SizeGreaterThan100_Rejected() throws Exception {
        mockMvc.perform(get("/audit/events").param("size", "101"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void testGetEvents_NegativePage_Rejected() throws Exception {
        mockMvc.perform(get("/audit/events").param("page", "-1"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void testGetEvents_FromGreaterThanTo_Rejected() throws Exception {
        mockMvc.perform(get("/audit/events")
                .param("from", "2024-02-01T00:00:00Z")
                .param("to", "2024-01-01T00:00:00Z"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void testGetEvents_EmptyResultReturnsValidEmptyPage() throws Exception {
        mockMvc.perform(get("/audit/events").param("actorId", "non-existent"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content", hasSize(0)))
                .andExpect(jsonPath("$.totalElements", is(0)));
    }

    @Test
    void testGetEvents_DeterministicTimestampOrdering() throws Exception {
        insertTestRecords();
        // Since r4 and r5 have the exact same timestamp, the secondary sorting (id ascending) will ensure determinism.
        mockMvc.perform(get("/audit/events"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content[0].timestamp").value("2024-01-01T10:00:00Z"))
                .andExpect(jsonPath("$.content[1].timestamp").value("2024-01-02T10:00:00Z"))
                .andExpect(jsonPath("$.content[2].timestamp").value("2024-01-03T10:00:00Z"))
                .andExpect(jsonPath("$.content[3].timestamp").value("2024-01-04T10:00:00Z"))
                .andExpect(jsonPath("$.content[4].timestamp").value("2024-01-04T10:00:00Z"));
    }

    // --- Append-Only Integrity Tests ---
    
    @Test
    void testUpdateOrDeleteMethodsNotSupported() throws Exception {
        // Assert PUT is not allowed on the collection
        mockMvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put("/audit/events")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{}"))
                .andExpect(status().isMethodNotAllowed());

        // Assert DELETE is not found (since we don't even map the ID path)
        mockMvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete("/audit/events/some-id"))
                .andExpect(status().isNotFound());
                
        // Assert PATCH is not found
        mockMvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch("/audit/events/some-id")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{}"))
                .andExpect(status().isNotFound());
    }
}
