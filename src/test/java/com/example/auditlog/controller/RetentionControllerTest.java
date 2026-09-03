package com.example.auditlog.controller;

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

@WebMvcTest(RetentionController.class)
@Import({DevSecurityConfig.class, RateLimitFilter.class})
@ActiveProfiles("dev")
@WithMockUser(authorities = {"SCOPE_audit:read", "SCOPE_audit:write", "SCOPE_audit:redact", "SCOPE_audit:archive", "SCOPE_audit:export", "SCOPE_audit:verify"})
public class RetentionControllerTest {

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
