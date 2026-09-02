package com.example.auditlog.security;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.options;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(properties = {
    "audit.cors.allowed-origins=http://localhost:3000"
})
@AutoConfigureMockMvc
@ActiveProfiles("dev")
public class CorsTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void corsPreflight_AllowedOrigin_Succeeds() throws Exception {
        mockMvc.perform(options("/audit/events")
                .header("Origin", "http://localhost:3000")
                .header("Access-Control-Request-Method", "GET"))
                .andExpect(status().isOk())
                .andExpect(header().string("Access-Control-Allow-Origin", "http://localhost:3000"));
    }

    @Test
    void corsPreflight_DisallowedOrigin_Rejected() throws Exception {
        mockMvc.perform(options("/audit/events")
                .header("Origin", "http://hacker.com")
                .header("Access-Control-Request-Method", "GET"))
                .andExpect(status().isForbidden());
    }
}
