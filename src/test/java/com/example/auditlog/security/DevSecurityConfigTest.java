package com.example.auditlog.security;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(properties = {"DEV_USER=devtest", "DEV_PASSWORD=devpass"})
@AutoConfigureMockMvc
@ActiveProfiles("dev")
public class DevSecurityConfigTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void requestWithoutAuth_Returns401() throws Exception {
        mockMvc.perform(get("/audit/events"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void requestWithInvalidAuth_Returns401() throws Exception {
        mockMvc.perform(get("/audit/events").with(httpBasic("wrong", "credentials")))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void requestWithValidAuth_Returns200() throws Exception {
        mockMvc.perform(get("/audit/events").with(httpBasic("devtest", "devpass")))
                .andExpect(status().isOk());
    }
}
