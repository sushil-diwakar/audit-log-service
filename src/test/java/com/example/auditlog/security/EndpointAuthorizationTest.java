package com.example.auditlog.security;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(properties = {
    "DEV_USER=test", "DEV_PASSWORD=test", 
    "spring.datasource.url=jdbc:h2:mem:auditdb;DB_CLOSE_DELAY=-1", 
    "spring.datasource.username=sa", "spring.datasource.driver-class-name=org.h2.Driver", "spring.datasource.password=",
    "OIDC_ISSUER_URI=https://mock.issuer", "OIDC_AUDIENCE=mock-audience"
})
@AutoConfigureMockMvc
@ActiveProfiles("dev")
public class EndpointAuthorizationTest {

    @org.springframework.test.context.DynamicPropertySource
    static void dynamicProperties(org.springframework.test.context.DynamicPropertyRegistry registry) throws Exception {
        java.security.KeyPairGenerator generator = java.security.KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        java.security.KeyPair pair = generator.generateKeyPair();
        registry.add("audit.signature.public-key", () -> java.util.Base64.getEncoder().encodeToString(pair.getPublic().getEncoded()));
        registry.add("audit.signature.private-key", () -> java.util.Base64.getEncoder().encodeToString(pair.getPrivate().getEncoded()));
        registry.add("audit.signature.key-id", () -> "test-key-dynamic");
        registry.add("audit.redaction.hmac-secret", () -> java.util.UUID.randomUUID().toString());
        registry.add("spring.datasource.url", () -> "jdbc:h2:mem:auditdb;DB_CLOSE_DELAY=-1");
        registry.add("spring.datasource.username", () -> "sa");
        registry.add("spring.datasource.password", () -> "");
        registry.add("spring.datasource.driver-class-name", () -> "org.h2.Driver");
        registry.add("DEV_USER", () -> "test");
        registry.add("DEV_PASSWORD", () -> "test");
    }

    @Autowired
    private MockMvc mockMvc;

    private static final String VALID_UUID = "123e4567-e89b-12d3-a456-426614174000";

    private final String VALID_EVENT_PAYLOAD = """
        {
          "eventType": "TEST",
          "actorId": "user",
          "resourceType": "SYS",
          "resourceId": "1",
          "payload": {},
          "timestamp": "2024-01-01T00:00:00Z"
        }
        """;

    // 1. POST /audit/events -> requires audit:write
    @Test
    @WithMockUser(authorities = "SCOPE_audit:read") // wrong scope
    void postEvents_wrongScope_403() throws Exception {
        mockMvc.perform(post("/audit/events").contentType("application/json").content(VALID_EVENT_PAYLOAD))
                .andExpect(status().isForbidden());
    }

    // 2. GET /audit/events -> requires audit:read
    @Test
    @WithMockUser(authorities = "SCOPE_audit:write") // wrong scope
    void getEvents_wrongScope_403() throws Exception {
        mockMvc.perform(get("/audit/events"))
                .andExpect(status().isForbidden());
    }

    // 3. GET /audit/verify -> requires audit:verify
    @Test
    @WithMockUser(authorities = "SCOPE_audit:read") // wrong scope
    void getVerify_wrongScope_403() throws Exception {
        mockMvc.perform(get("/audit/verify"))
                .andExpect(status().isForbidden());
    }

    // 4. GET /audit/export -> requires audit:export
    @Test
    @WithMockUser(authorities = "SCOPE_audit:archive") // wrong scope
    void getExport_wrongScope_403() throws Exception {
        mockMvc.perform(get("/audit/export").param("actorId", "user"))
                .andExpect(status().isForbidden());
    }

    // 5. POST /audit/events/{id}/redact -> requires audit:redact
    @Test
    @WithMockUser(authorities = "SCOPE_audit:write") // wrong scope
    void postRedact_wrongScope_403() throws Exception {
        mockMvc.perform(post("/audit/events/" + VALID_UUID + "/redact").contentType("application/json").content("{\"paths\":[\"/foo\"]}"))
                .andExpect(status().isForbidden());
    }

    // 6. POST /audit/retention/archive -> requires audit:archive
    @Test
    @WithMockUser(authorities = "SCOPE_audit:export") // wrong scope
    void postArchive_wrongScope_403() throws Exception {
        mockMvc.perform(post("/audit/retention/archive").param("before", "2024-01-01T00:00:00Z"))
                .andExpect(status().isForbidden());
    }

    // 7. POST /audit/export/verify -> no scope required (anonymous)
    @Test
    void postExportVerify_anonymous_200() throws Exception {
        mockMvc.perform(post("/audit/export/verify").contentType("application/json").content("{}"))
                .andExpect(status().isOk());
    }

    // Verify correct scopes return 400/200/404 (i.e. pass authorization)
    @Test
    @WithMockUser(authorities = "SCOPE_audit:write")
    void postEvents_correctScope_passesAuth() throws Exception {
        mockMvc.perform(post("/audit/events").contentType("application/json").content("{}"))
                .andExpect(status().isBadRequest()); // passes auth, fails validation
    }

    @Test
    @WithMockUser(authorities = "SCOPE_audit:read")
    void getEvents_correctScope_passesAuth() throws Exception {
        mockMvc.perform(get("/audit/events"))
                .andExpect(status().isOk()); // passes auth
    }
}
