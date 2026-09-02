package com.example.auditlog.security;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(properties = {"OIDC_ISSUER_URI=https://mock.issuer", "OIDC_AUDIENCE=mock-audience", "PROD_ALLOWED_ORIGINS=http://localhost:3000"})
@AutoConfigureMockMvc
@ActiveProfiles("prod")
public class ProdSecurityConfigTest {

    @MockBean
    private JwtDecoder jwtDecoder;

    @Autowired
    private MockMvc mockMvc;

    @Test
    void requestWithoutJwt_Returns401() throws Exception {
        mockMvc.perform(get("/audit/events"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void requestWithValidJwt_Returns200() throws Exception {
        mockMvc.perform(get("/audit/events").with(jwt()))
                .andExpect(status().isOk());
    }
}
