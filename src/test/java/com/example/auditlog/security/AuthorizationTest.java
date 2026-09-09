package com.example.auditlog.security;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.context.TestPropertySource;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(properties = {
    "DEV_USER=test", "DEV_PASSWORD=test", 
    "spring.datasource.url=jdbc:h2:mem:auditdb;DB_CLOSE_DELAY=-1;MODE=MySQL", 
    "spring.datasource.username=sa", "spring.datasource.driver-class-name=org.h2.Driver", "spring.datasource.password="
})
@AutoConfigureMockMvc
@ActiveProfiles("dev")
@TestPropertySource(properties = "spring.jpa.hibernate.ddl-auto=create-drop")
public class AuthorizationTest {

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

    private static final String PAYLOAD = "{\"eventType\":\"TEST\", \"actorId\":\"test\", \"resourceType\":\"SYS\", \"resourceId\":\"1\", \"payload\":{}}";

    @Test
    void unauthenticatedAccess_Returns401() throws Exception {
        mockMvc.perform(get("/audit/events")).andExpect(status().isUnauthorized());
        mockMvc.perform(post("/audit/events").contentType(MediaType.APPLICATION_JSON).content(PAYLOAD).with(csrf())).andExpect(status().isUnauthorized());
        mockMvc.perform(get("/audit/verify")).andExpect(status().isUnauthorized());
        mockMvc.perform(get("/audit/export?resourceId=1")).andExpect(status().isUnauthorized());
        mockMvc.perform(post("/audit/events/123e4567-e89b-12d3-a456-426614174000/redact").contentType(MediaType.APPLICATION_JSON).content("{\"paths\":[]}").with(csrf())).andExpect(status().isUnauthorized());
        mockMvc.perform(post("/audit/retention/archive?before=2025-01-01T00:00:00Z").with(csrf())).andExpect(status().isUnauthorized());
    }

    @Test
    void writeEndpoint_RequiresWriteScope() throws Exception {
        mockMvc.perform(post("/audit/events")
                .contentType(MediaType.APPLICATION_JSON).content(PAYLOAD).with(csrf())
                .with(user("u").authorities(new SimpleGrantedAuthority("SCOPE_audit:read"))))
                .andExpect(status().isForbidden());
                
        mockMvc.perform(post("/audit/events")
                .contentType(MediaType.APPLICATION_JSON).content(PAYLOAD).with(csrf())
                .with(user("u").authorities(new SimpleGrantedAuthority("SCOPE_audit:write"))))
                .andExpect(status().is2xxSuccessful());
    }

    @Test
    void readEndpoint_RequiresReadScope() throws Exception {
        mockMvc.perform(get("/audit/events")
                .with(user("u").authorities(new SimpleGrantedAuthority("SCOPE_audit:write"))))
                .andExpect(status().isForbidden());

        mockMvc.perform(get("/audit/events")
                .with(user("u").authorities(new SimpleGrantedAuthority("SCOPE_audit:read"))))
                .andExpect(status().isOk());
    }

    @Test
    void verifyEndpoint_RequiresVerifyScope() throws Exception {
        mockMvc.perform(get("/audit/verify")
                .with(user("u").authorities(new SimpleGrantedAuthority("SCOPE_audit:read"))))
                .andExpect(status().isForbidden());

        mockMvc.perform(get("/audit/verify")
                .with(user("u").authorities(new SimpleGrantedAuthority("SCOPE_audit:verify"))))
                .andExpect(status().isOk());
    }

    @Test
    void exportEndpoint_RequiresExportScope() throws Exception {
        mockMvc.perform(get("/audit/export?resourceId=1")
                .with(user("u").authorities(new SimpleGrantedAuthority("SCOPE_audit:read"))))
                .andExpect(status().isForbidden());

        mockMvc.perform(get("/audit/export?resourceId=1")
                .with(user("u").authorities(new SimpleGrantedAuthority("SCOPE_audit:export"))))
                .andExpect(status().isOk());
    }

    @Test
    void redactEndpoint_RequiresRedactScope() throws Exception {
        mockMvc.perform(post("/audit/events/123e4567-e89b-12d3-a456-426614174000/redact")
                .contentType(MediaType.APPLICATION_JSON).content("{\"paths\":[\"/a\"]}").with(csrf())
                .with(user("u").authorities(new SimpleGrantedAuthority("SCOPE_audit:write"))))
                .andExpect(status().isForbidden());
        // A valid ID is needed for 2xx, but 404 indicates we passed authz
        mockMvc.perform(post("/audit/events/123e4567-e89b-12d3-a456-426614174000/redact")
                .contentType(MediaType.APPLICATION_JSON).content("{\"paths\":[\"/a\"]}").with(csrf())
                .with(user("u").authorities(new SimpleGrantedAuthority("SCOPE_audit:redact"))))
                .andExpect(status().isNotFound()); // Or 400, but not 401/403
    }

    @Test
    void archiveEndpoint_RequiresArchiveScope() throws Exception {
        mockMvc.perform(post("/audit/retention/archive?before=2025-01-01T00:00:00Z").with(csrf())
                .with(user("u").authorities(new SimpleGrantedAuthority("SCOPE_audit:write"))))
                .andExpect(status().isForbidden());

        mockMvc.perform(post("/audit/retention/archive?before=2025-01-01T00:00:00Z").with(csrf())
                .with(user("u").authorities(new SimpleGrantedAuthority("SCOPE_audit:archive"))))
                .andExpect(status().isOk());
    }
}
