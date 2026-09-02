package com.example.auditlog.controller;

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

@WebMvcTest(VerificationController.class)
@Import({DevSecurityConfig.class, RateLimitFilter.class})
@ActiveProfiles("dev")
@WithMockUser
class VerificationControllerTest {

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
