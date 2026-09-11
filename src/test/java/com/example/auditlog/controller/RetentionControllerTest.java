package com.example.auditlog.controller;

import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;

import com.example.auditlog.dto.ArchivalResponse;
import com.example.auditlog.service.RetentionService;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import com.example.auditlog.config.DevSecurityConfig;
import com.example.auditlog.config.RateLimitFilter;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.security.test.context.support.WithMockUser;

import java.time.Instant;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("dev")
@WithMockUser(authorities = {"SCOPE_audit:archive"})
public class RetentionControllerTest {

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

    @MockBean
    private RetentionService retentionService;

    @Test
    void testArchiveEndpoint() throws Exception {
        Instant cutoff = Instant.parse("2024-05-01T00:00:00Z");
        
        ArchivalResponse mockResponse = ArchivalResponse.builder()
                .archivedCount(5)
                .cutoffTimestamp(cutoff)
                .build();
                
        Mockito.when(retentionService.archiveRecordsBefore(cutoff)).thenReturn(mockResponse);

        mockMvc.perform(post("/audit/retention/archive")
                .param("before", "2024-05-01T00:00:00Z"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.archivedCount").value(5))
                .andExpect(jsonPath("$.cutoffTimestamp").value("2024-05-01T00:00:00Z"));
    }
}
