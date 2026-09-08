package com.example.auditlog.validation;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import com.example.auditlog.repository.AuditRecordRepository;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(properties = {
    "DEV_USER=test", "DEV_PASSWORD=test", "audit.redaction.hmac-secret=test-secret", "DB_URL=jdbc:mysql://localhost:3306/auditdb?useSSL=false&allowPublicKeyRetrieval=true", "DB_USERNAME=root", "DB_PASSWORD=root","OIDC_ISSUER_URI=https://mock.issuer", "OIDC_AUDIENCE=mock-audience", "audit.signature.key-id=test-key-1", "audit.signature.private-key=MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCYcAMNLx3WHc9xI8rBJKUFNDgEOyxNKnAjGRtX4pCHAQMcOUtehnMMyJo6dTPT+4fhw0V1S2D4szI0QhZoj9bn8e6rpA2uecoZ2UJenCXNFEqZsahkoOHXh+Oi+a0RTNoBmesWFGWQSiMu/QhPLJkBn29eEcu+GYveB1oMWwUXOZj6Fk0DtiiZRoI9T/QwYcUqpJ/LBweY4S/atU5ZvuMWRPEfOyjHEL/Xm6kkfK2/sc/i9FqT1HF0fkNugLo1Bjz7gYloRyUmLbuEdyA3pHVLl2Db6TpEj8HcnpZvBwkO+8s4chXY7P4HVnHErNynXvKRtk01IrY1bq3FKY7Lzr4hAgMBAAECgf9uwPN2oMUMzJvrmBW4Puem4EnSyStm5W6UEanMMNDRRer8lqQsCYONxjJIRt9hJV+UqEvO7PWHvKq9TUb6sYdy/lRqYMeP/OzZ2wBdvRW56wRIpsuyUTHFZvX9c2pLJ4s9npcvc6JXM4ZcnXtsCvsgMra3ojZl6Cm3J6BFWdxZAmENw0iLRKl9aL9Wunrr7K0E8OSlZBy78V9I8YUIoRiHdQ1Cy/Pk53pe+EM9faioBtpd6evo92OXG9b3/+qxWCi2mEtWXPYjxj27bGwA4BI31RKjdO9yEPRcAlQwYPJVVGGPGRDxdg6BeX8vSBME2qg2ol59DBPSQwgmjf1NsgECgYEAyEIIHQ6hq5YvFgot5NTWyX8slLi0R4Dg+W4Z9LPl/Sg2Ur2RXEqwh4V/vkMc7Zd8LXBnrAe/45R0nJK0Fr4lTBgZQ/HjDj5yuRPwXQSqY86fXkQ/keFsVXIqkCmnAM+Cy8OPC+JYm4pN2g5ykPqTR63Lm1R0r9tvui2YjnG7IDECgYEAwt5lzzDhR6roTOQGyET25FlqZnqIwqyR9WwsIqAjCt+IUFFbDZl527oYSu96Ckbr/L6RylENQslUwkdgEJ5u6I0JSw+i/XBaJCaqVeFdD/u5rJxwcBdv8rYzw+8RZNv+5XWam8yQQYBucERL1OVS/sEbcQVEpM/lAMmvFpGQcPECgYAGKQHW4vxWKuiH5QhEYce5qw/UA1qIWI6THa/utxn8D6CcKvitvh5wDMtBLw9Uv7QyMaL+x74/YfG0X07q5C6BiLw+OtKhPYqJ5vMd6WbUaya7352U/zo15q0ogh+BBuEfI4Ti+LOBFWAPtSIRE6Q0MERzIsX0Iuvs7jojJ5x6AQKBgQCKnJl8pH9KdDZjIzvzzqJz0WqO1JBdMVVtZnGKe7ARdulGgGgtJ0N32UqYWvnLP6FzGbcoWzj8jatdulmJ2Lh5cIDwxIGilv13g41cIz8INH1hW7Ha+cDmu1XdBDuyK46Hd3zvX7Yo8YsdDmeGW00K6x9y6FVoinyRb+S8P/SncQKBgQCq4f/996kpehmS9NHeN5R10UgFEdl9l/2nM1MMQWV2oxIc6LInW/ATRCtuGaXfceefBdJ4NPAzBrm8k8I22pVuO6HLNW1Kqpo5wYJ7zFjeplZgp6crVVZg15NI4gQS2PcV4S4zbS1vZ3/FQDWhyB/UXWQqb6XjFj1hPJSRaS0Spg==", "audit.signature.public-key=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmHADDS8d1h3PcSPKwSSlBTQ4BDssTSpwIxkbV+KQhwEDHDlLXoZzDMiaOnUz0/uH4cNFdUtg+LMyNEIWaI/W5/Huq6QNrnnKGdlCXpwlzRRKmbGoZKDh14fjovmtEUzaAZnrFhRlkEojLv0ITyyZAZ9vXhHLvhmL3gdaDFsFFzmY+hZNA7YomUaCPU/0MGHFKqSfywcHmOEv2rVOWb7jFkTxHzsoxxC/15upJHytv7HP4vRak9RxdH5DboC6NQY8+4GJaEclJi27hHcgN6R1S5dg2+k6RI/B3J6WbwcJDvvLOHIV2Oz+B1ZxxKzcp17ykbZNNSK2NW6txSmOy86+IQIDAQAB"
})
@AutoConfigureMockMvc
@ActiveProfiles("dev")
public class ValidationIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private AuditRecordRepository repository;

    @org.junit.jupiter.api.BeforeEach
    void setUp() {
        repository.deleteAll();
    }

    @Test
    @WithMockUser(authorities = "SCOPE_audit:read")
    void getEvents_invalidPagination_Returns400() throws Exception {
        mockMvc.perform(get("/audit/events").param("page", "-1").param("size", "0"))
                .andExpect(status().isBadRequest());
    }
    
    @Test
    @WithMockUser(authorities = "SCOPE_audit:read")
    void getEvents_invalidTimeRange_Returns400() throws Exception {
        // from > to
        mockMvc.perform(get("/audit/events").param("from", "2024-01-02T00:00:00Z").param("to", "2024-01-01T00:00:00Z"))
                .andExpect(status().isBadRequest());
    }

    @Test
    @WithMockUser(authorities = "SCOPE_audit:write")
    void postEvents_oversizedString_Returns400() throws Exception {
        String hugeString = "a".repeat(200);
        String payload = """
            {
              "eventType": "%s",
              "actorId": "user1",
              "resourceType": "SYS",
              "resourceId": "1",
              "payload": {"a": "b"},
              "timestamp": "2024-01-01T00:00:00Z"
            }
            """.formatted(hugeString);
            
        mockMvc.perform(post("/audit/events").contentType("application/json").content(payload))
                .andExpect(status().isBadRequest());
    }

    @Test
    @WithMockUser(authorities = "SCOPE_audit:write")
    void postEvents_malformedJson_Returns400() throws Exception {
        mockMvc.perform(post("/audit/events").contentType("application/json").content("{ malformed_json"))
                .andExpect(status().isBadRequest());
    }

    @Test
    @WithMockUser(authorities = "SCOPE_audit:redact")
    void postRedact_invalidUuid_Returns400() throws Exception {
        mockMvc.perform(post("/audit/events/not-a-uuid/redact").contentType("application/json").content("{\"paths\":[\"/foo\"]}"))
                .andExpect(status().isBadRequest());
    }

    @Test
    @WithMockUser(authorities = "SCOPE_audit:redact")
    void postRedact_emptyPaths_Returns400() throws Exception {
        mockMvc.perform(post("/audit/events/123e4567-e89b-12d3-a456-426614174000/redact").contentType("application/json").content("{\"paths\":[]}"))
                .andExpect(status().isBadRequest());
    }
    
    @Test
    @WithMockUser(authorities = "SCOPE_audit:redact")
    void postRedact_overlappingPaths_Returns400() throws Exception {
        // I will first create an event, then try to redact it with overlapping paths
        String payload = """
            {
              "eventType": "TEST",
              "actorId": "user1",
              "resourceType": "SYS",
              "resourceId": "1",
              "payload": {"a": {"b": "c"}},
              "timestamp": "2024-01-01T00:00:00Z"
            }
            """;
        String response = mockMvc.perform(post("/audit/events").contentType("application/json").content(payload).with(org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user("user").authorities(new org.springframework.security.core.authority.SimpleGrantedAuthority("SCOPE_audit:write"))))
            .andExpect(status().isCreated())
            .andReturn().getResponse().getContentAsString();
        
        String id = new com.fasterxml.jackson.databind.ObjectMapper().readTree(response).get("id").asText();
        
        mockMvc.perform(post("/audit/events/" + id + "/redact").contentType("application/json").content("{\"paths\":[\"/a\", \"/a/b\"]}"))
                .andExpect(status().isBadRequest());
    }
}
