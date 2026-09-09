package com.example.auditlog.controller;

import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;

import com.example.auditlog.dto.VerificationResponse;
import com.example.auditlog.service.ChainVerificationService;
import org.junit.jupiter.api.Test;
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

import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("dev")
public class VerificationControllerTest {

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
        registry.add("spring.datasource.url", () -> "jdbc:h2:mem:auditdb;DB_CLOSE_DELAY=-1;MODE=MySQL");
        registry.add("spring.datasource.username", () -> "sa");
        registry.add("spring.datasource.driver-class-name", () -> "org.h2.Driver");
        registry.add("DEV_USER", () -> "test");
        registry.add("DEV_PASSWORD", () -> "test");
        registry.add("spring.datasource.password", () -> "test");
        registry.add("DEV_USER", () -> "test");
        registry.add("DEV_PASSWORD", () -> "test");
    }

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private ChainVerificationService chainVerificationService;

    @Test
    void testVerifyChain_Success() throws Exception {
        VerificationResponse mockResponse = VerificationResponse.builder()
                .valid(true)
                .message("Audit chain is intact")
                .checkedRecords(10)
                .build();

        when(chainVerificationService.verifyChain()).thenReturn(mockResponse);

        mockMvc.perform(get("/audit/verify"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.valid").value(true))
                .andExpect(jsonPath("$.message").value("Audit chain is intact"))
                .andExpect(jsonPath("$.checkedRecords").value(10))
                .andExpect(jsonPath("$.violationType").doesNotExist());
    }

    @Test
    void testVerifyChain_Failure() throws Exception {
        VerificationResponse mockResponse = VerificationResponse.builder()
                .valid(false)
                .message("Record hash mismatch detected")
                .violationType(com.example.auditlog.enums.ChainViolationType.RECORD_HASH_MISMATCH)
                .checkedRecords(5)
                .build();

        when(chainVerificationService.verifyChain()).thenReturn(mockResponse);

        mockMvc.perform(get("/audit/verify"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.valid").value(false))
                .andExpect(jsonPath("$.message").value("Record hash mismatch detected"))
                .andExpect(jsonPath("$.checkedRecords").value(5))
                .andExpect(jsonPath("$.violationType").value("RECORD_HASH_MISMATCH"));
    }
}
