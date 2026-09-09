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
    "DEV_USER=test", "DEV_PASSWORD=test", 
    "spring.datasource.url=jdbc:h2:mem:auditdb;DB_CLOSE_DELAY=-1;MODE=MySQL", 
    "spring.datasource.username=sa", "spring.datasource.driver-class-name=org.h2.Driver", "spring.datasource.password=",
    "OIDC_ISSUER_URI=https://mock.issuer", "OIDC_AUDIENCE=mock-audience"
})
@AutoConfigureMockMvc
@ActiveProfiles("dev")
public class ValidationIntegrationTest {

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
