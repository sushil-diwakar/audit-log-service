package com.example.auditlog;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import static org.hamcrest.Matchers.hasSize;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@TestPropertySource(properties = "spring.jpa.hibernate.ddl-auto=create-drop")
class ScenarioAEndToEndTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @BeforeEach
    void setUp() {
        jdbcTemplate.execute("DELETE FROM audit_records");
    }

    @Test
    void testFullScenarioAFlow() throws Exception {
        // 1. POST/create event 1
        String payload1 = """
            {
                "eventType": "LOGIN",
                "actorId": "user-A",
                "resourceType": "ACCOUNT",
                "resourceId": "acc-1",
                "payload": {"ip": "192.168.1.1"}
            }
        """;
        mockMvc.perform(post("/audit/events").contentType(MediaType.APPLICATION_JSON).content(payload1))
                .andExpect(status().isCreated());

        // 2. POST/create event 2
        String payload2 = """
            {
                "eventType": "TRANSFER",
                "actorId": "user-A",
                "resourceType": "FUNDS",
                "resourceId": "txn-99",
                "payload": {"amount": 500}
            }
        """;
        mockMvc.perform(post("/audit/events").contentType(MediaType.APPLICATION_JSON).content(payload2))
                .andExpect(status().isCreated());

        // 3. POST/create event 3
        String payload3 = """
            {
                "eventType": "LOGOUT",
                "actorId": "user-A",
                "resourceType": "ACCOUNT",
                "resourceId": "acc-1",
                "payload": {"duration": 300}
            }
        """;
        mockMvc.perform(post("/audit/events").contentType(MediaType.APPLICATION_JSON).content(payload3))
                .andExpect(status().isCreated());

        // 4. GET /audit/events (Query validation)
        mockMvc.perform(get("/audit/events").param("actorId", "user-A"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content", hasSize(3)))
                .andExpect(jsonPath("$.totalElements").value(3));

        // 5. GET /audit/verify -> valid
        mockMvc.perform(get("/audit/verify"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.valid").value(true))
                .andExpect(jsonPath("$.checkedRecords").value(3))
                .andExpect(jsonPath("$.violationType").doesNotExist());

        // 6. Direct DB tampering (simulate attacker)
        // We modify event 2's payload maliciously, bypassing the API entirely
        int rows = jdbcTemplate.update("UPDATE audit_records SET payload = '{\"amount\": 99999}' WHERE event_type = 'TRANSFER'");
        assert rows == 1;

        // 7. GET /audit/verify -> invalid
        mockMvc.perform(get("/audit/verify"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.valid").value(false))
                .andExpect(jsonPath("$.violationType").value("RECORD_HASH_MISMATCH"));
    }
}
