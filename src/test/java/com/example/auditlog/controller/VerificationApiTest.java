package com.example.auditlog.controller;

import com.example.auditlog.dto.VerificationResponse;
import com.example.auditlog.service.ChainVerificationService;
import com.example.auditlog.enums.ChainViolationType;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest(properties = {
    "DEV_USER=test", "DEV_PASSWORD=test", 
    "spring.datasource.url=jdbc:h2:mem:auditdb;DB_CLOSE_DELAY=-1", 
    "spring.datasource.username=sa", "spring.datasource.driver-class-name=org.h2.Driver", "spring.datasource.password="
})
@AutoConfigureMockMvc
@ActiveProfiles("dev")
public class VerificationApiTest {

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
    private ChainVerificationService chainVerificationService;

    @Test
    @WithMockUser(authorities = "SCOPE_audit:verify")
    void testValidChain_Returns200AndValidTrue() throws Exception {
        VerificationResponse response = VerificationResponse.builder()
                .valid(true)
                .checkedRecords(10)
                .build();
                
        when(chainVerificationService.verifyChain()).thenReturn(response);
        
        mockMvc.perform(get("/audit/verify"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.valid").value(true))
                .andExpect(jsonPath("$.checkedRecords").value(10));
    }

    @Test
    @WithMockUser(authorities = "SCOPE_audit:verify")
    void testInvalidChain_Returns200AndValidFalseWithViolationInfo() throws Exception {
        VerificationResponse response = VerificationResponse.builder()
                .valid(false)
                .violationType(ChainViolationType.CONTENT_HASH_MISMATCH)
                .recordId(java.util.UUID.randomUUID())
                .build();
                
        when(chainVerificationService.verifyChain()).thenReturn(response);
        
        mockMvc.perform(get("/audit/verify"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.valid").value(false))
                .andExpect(jsonPath("$.violationType").value("CONTENT_HASH_MISMATCH"));
    }
}
