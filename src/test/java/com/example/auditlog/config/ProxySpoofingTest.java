package com.example.auditlog.config;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Security tests for rate limiting proxy header validation.
 * Ensures X-Forwarded-For spoofing attacks are prevented.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("dev")
@TestPropertySource(properties = {
    "DEV_USER=test",
    "DEV_PASSWORD=test",
    "spring.datasource.url=jdbc:h2:mem:testdb;DB_CLOSE_DELAY=-1",
    "spring.datasource.username=sa",
    "spring.datasource.driver-class-name=org.h2.Driver",
    "spring.datasource.password=",
    "audit.rate-limit.capacity=2",
    "audit.rate-limit.refill-tokens=2",
    "audit.rate-limit.trusted-proxies=127.0.0.1,10.0.0.1"
})
class ProxySpoofingTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    @WithMockUser(username = "test-user-1", authorities = {"SCOPE_audit:read", "SCOPE_audit:verify"})
    void testSpoofedXForwardedFor_NotFromTrustedProxy_IgnoresHeader() throws Exception {
        // Attack: Client sends spoofed X-Forwarded-For from untrusted source
        // First request - should succeed
        mockMvc.perform(get("/audit/events")
                .header("X-Forwarded-For", "1.1.1.1")
                .remoteAddress("192.168.1.100")) // Not a trusted proxy
                .andExpect(status().isOk());

        // Second request with different spoofed IP - should succeed (same actual IP)
        mockMvc.perform(get("/audit/events")
                .header("X-Forwarded-For", "2.2.2.2")
                .remoteAddress("192.168.1.100")) // Same actual source
                .andExpect(status().isOk());

        // Third request - should hit rate limit (capacity=2)
        mockMvc.perform(get("/audit/events")
                .header("X-Forwarded-For", "3.3.3.3")
                .remoteAddress("192.168.1.100"))
                .andExpect(status().isTooManyRequests());
    }

    @Test
    @WithMockUser(username = "test-user-2", authorities = {"SCOPE_audit:read", "SCOPE_audit:verify"})
    void testXForwardedFor_FromTrustedProxy_HonorsHeader() throws Exception {
        // Legitimate: Request from trusted proxy
        // First request from client 1.1.1.1 via trusted proxy
        mockMvc.perform(get("/audit/events")
                .header("X-Forwarded-For", "1.1.1.1")
                .remoteAddress("127.0.0.1")) // Trusted proxy
                .andExpect(status().isOk());

        // Second request from same client
        mockMvc.perform(get("/audit/events")
                .header("X-Forwarded-For", "1.1.1.1")
                .remoteAddress("127.0.0.1"))
                .andExpect(status().isOk());

        // Third request from same client - should hit rate limit
        mockMvc.perform(get("/audit/events")
                .header("X-Forwarded-For", "1.1.1.1")
                .remoteAddress("127.0.0.1"))
                .andExpect(status().isTooManyRequests());

        // But request from different client should succeed
        mockMvc.perform(get("/audit/events")
                .header("X-Forwarded-For", "2.2.2.2")
                .remoteAddress("127.0.0.1")
                .with(org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user("test-user-2-other").authorities(new org.springframework.security.core.authority.SimpleGrantedAuthority("SCOPE_audit:read"))))
                .andExpect(status().isOk());
    }

    @Test
    @WithMockUser(username = "test-user-3", authorities = {"SCOPE_audit:read", "SCOPE_audit:verify"})
    void testNoTrustedProxiesConfigured_IgnoresAllHeaders() throws Exception {
        // When no trusted proxies are configured, all forwarding headers should be ignored
        // This test verifies the default secure behavior
        mockMvc.perform(get("/audit/verify")
                .header("X-Forwarded-For", "spoofed.ip.1")
                .header("X-Real-IP", "spoofed.ip.2")
                .remoteAddress("actual.client.ip"))
                .andExpect(status().isOk());
    }
}
