package com.example.auditlog.security;

import org.junit.jupiter.api.Test;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(properties = {
    "audit.rate-limit.capacity=2",
    "audit.rate-limit.refill-tokens=2"
})
@AutoConfigureMockMvc
@ActiveProfiles("dev")
public class RateLimitTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void rateLimiter_EnforcesLimitsPerPrincipal() throws Exception {
        // Request 1: OK
        mockMvc.perform(get("/audit/events").with(user("user1").authorities(new SimpleGrantedAuthority("SCOPE_audit:read"))))
                .andExpect(status().isOk());
        // Request 2: OK
        mockMvc.perform(get("/audit/events").with(user("user1").authorities(new SimpleGrantedAuthority("SCOPE_audit:read"))))
                .andExpect(status().isOk());
        // Request 3: 429 Too Many Requests
        mockMvc.perform(get("/audit/events").with(user("user1").authorities(new SimpleGrantedAuthority("SCOPE_audit:read"))))
                .andExpect(status().isTooManyRequests());

        // A different user should have their own bucket
        mockMvc.perform(get("/audit/events").with(user("user2").authorities(new SimpleGrantedAuthority("SCOPE_audit:read"))))
                .andExpect(status().isOk());
    }
}
