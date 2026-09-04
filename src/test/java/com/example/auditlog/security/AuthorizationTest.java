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

@SpringBootTest(properties = {"DEV_USER=test", "DEV_PASSWORD=test", "audit.signature.key-id=test-key-1", "audit.signature.private-key=MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCYcAMNLx3WHc9xI8rBJKUFNDgEOyxNKnAjGRtX4pCHAQMcOUtehnMMyJo6dTPT+4fhw0V1S2D4szI0QhZoj9bn8e6rpA2uecoZ2UJenCXNFEqZsahkoOHXh+Oi+a0RTNoBmesWFGWQSiMu/QhPLJkBn29eEcu+GYveB1oMWwUXOZj6Fk0DtiiZRoI9T/QwYcUqpJ/LBweY4S/atU5ZvuMWRPEfOyjHEL/Xm6kkfK2/sc/i9FqT1HF0fkNugLo1Bjz7gYloRyUmLbuEdyA3pHVLl2Db6TpEj8HcnpZvBwkO+8s4chXY7P4HVnHErNynXvKRtk01IrY1bq3FKY7Lzr4hAgMBAAECgf9uwPN2oMUMzJvrmBW4Puem4EnSyStm5W6UEanMMNDRRer8lqQsCYONxjJIRt9hJV+UqEvO7PWHvKq9TUb6sYdy/lRqYMeP/OzZ2wBdvRW56wRIpsuyUTHFZvX9c2pLJ4s9npcvc6JXM4ZcnXtsCvsgMra3ojZl6Cm3J6BFWdxZAmENw0iLRKl9aL9Wunrr7K0E8OSlZBy78V9I8YUIoRiHdQ1Cy/Pk53pe+EM9faioBtpd6evo92OXG9b3/+qxWCi2mEtWXPYjxj27bGwA4BI31RKjdO9yEPRcAlQwYPJVVGGPGRDxdg6BeX8vSBME2qg2ol59DBPSQwgmjf1NsgECgYEAyEIIHQ6hq5YvFgot5NTWyX8slLi0R4Dg+W4Z9LPl/Sg2Ur2RXEqwh4V/vkMc7Zd8LXBnrAe/45R0nJK0Fr4lTBgZQ/HjDj5yuRPwXQSqY86fXkQ/keFsVXIqkCmnAM+Cy8OPC+JYm4pN2g5ykPqTR63Lm1R0r9tvui2YjnG7IDECgYEAwt5lzzDhR6roTOQGyET25FlqZnqIwqyR9WwsIqAjCt+IUFFbDZl527oYSu96Ckbr/L6RylENQslUwkdgEJ5u6I0JSw+i/XBaJCaqVeFdD/u5rJxwcBdv8rYzw+8RZNv+5XWam8yQQYBucERL1OVS/sEbcQVEpM/lAMmvFpGQcPECgYAGKQHW4vxWKuiH5QhEYce5qw/UA1qIWI6THa/utxn8D6CcKvitvh5wDMtBLw9Uv7QyMaL+x74/YfG0X07q5C6BiLw+OtKhPYqJ5vMd6WbUaya7352U/zo15q0ogh+BBuEfI4Ti+LOBFWAPtSIRE6Q0MERzIsX0Iuvs7jojJ5x6AQKBgQCKnJl8pH9KdDZjIzvzzqJz0WqO1JBdMVVtZnGKe7ARdulGgGgtJ0N32UqYWvnLP6FzGbcoWzj8jatdulmJ2Lh5cIDwxIGilv13g41cIz8INH1hW7Ha+cDmu1XdBDuyK46Hd3zvX7Yo8YsdDmeGW00K6x9y6FVoinyRb+S8P/SncQKBgQCq4f/996kpehmS9NHeN5R10UgFEdl9l/2nM1MMQWV2oxIc6LInW/ATRCtuGaXfceefBdJ4NPAzBrm8k8I22pVuO6HLNW1Kqpo5wYJ7zFjeplZgp6crVVZg15NI4gQS2PcV4S4zbS1vZ3/FQDWhyB/UXWQqb6XjFj1hPJSRaS0Spg==", "audit.signature.public-key=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmHADDS8d1h3PcSPKwSSlBTQ4BDssTSpwIxkbV+KQhwEDHDlLXoZzDMiaOnUz0/uH4cNFdUtg+LMyNEIWaI/W5/Huq6QNrnnKGdlCXpwlzRRKmbGoZKDh14fjovmtEUzaAZnrFhRlkEojLv0ITyyZAZ9vXhHLvhmL3gdaDFsFFzmY+hZNA7YomUaCPU/0MGHFKqSfywcHmOEv2rVOWb7jFkTxHzsoxxC/15upJHytv7HP4vRak9RxdH5DboC6NQY8+4GJaEclJi27hHcgN6R1S5dg2+k6RI/B3J6WbwcJDvvLOHIV2Oz+B1ZxxKzcp17ykbZNNSK2NW6txSmOy86+IQIDAQAB"})
@AutoConfigureMockMvc
@ActiveProfiles("dev")
@TestPropertySource(properties = "spring.jpa.hibernate.ddl-auto=create-drop")
public class AuthorizationTest {

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