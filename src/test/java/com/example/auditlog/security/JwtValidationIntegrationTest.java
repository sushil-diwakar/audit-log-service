package com.example.auditlog.security;

import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import com.example.auditlog.config.AudienceValidator;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(properties = {
        "DEV_USER=test", "DEV_PASSWORD=test", 
        "spring.datasource.url=jdbc:h2:mem:auditdb;DB_CLOSE_DELAY=-1", 
        "spring.datasource.username=sa", "spring.datasource.driver-class-name=org.h2.Driver", "spring.datasource.password=",
        "OIDC_ISSUER_URI=https://mock.issuer", 
        "audit.security.oauth2.audience=mock-audience", 
        "PROD_ALLOWED_ORIGINS=http://localhost:3000"
})
@AutoConfigureMockMvc
@ActiveProfiles("prod")
public class JwtValidationIntegrationTest {

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

    private static RSAKey rsaKey;
    private static RSAKey wrongKey;
    private static NimbusJwtEncoder jwtEncoder;
    private static NimbusJwtEncoder wrongEncoder;

    @BeforeAll
    static void setUp() throws Exception {
        rsaKey = new RSAKeyGenerator(2048).keyID("test-key").generate();
        wrongKey = new RSAKeyGenerator(2048).keyID("wrong-key").generate();
        
        com.nimbusds.jose.jwk.JWKSet jwkSet = new com.nimbusds.jose.jwk.JWKSet(rsaKey);
        com.nimbusds.jose.jwk.source.ImmutableJWKSet<com.nimbusds.jose.proc.SecurityContext> jwkSource = new com.nimbusds.jose.jwk.source.ImmutableJWKSet<>(jwkSet);
        jwtEncoder = new NimbusJwtEncoder(jwkSource);

        com.nimbusds.jose.jwk.JWKSet wrongSet = new com.nimbusds.jose.jwk.JWKSet(wrongKey);
        com.nimbusds.jose.jwk.source.ImmutableJWKSet<com.nimbusds.jose.proc.SecurityContext> wrongSource = new com.nimbusds.jose.jwk.source.ImmutableJWKSet<>(wrongSet);
        wrongEncoder = new NimbusJwtEncoder(wrongSource);
    }

    @MockBean
    private JwtDecoder springMockDecoder;
    
    private JwtDecoder realNimbusDecoder;

    @BeforeEach
    void setupRealDecoder() throws Exception {
        realNimbusDecoder = NimbusJwtDecoder.withPublicKey(rsaKey.toRSAPublicKey()).build();
        OAuth2TokenValidator<Jwt> withIssuer = JwtValidators.createDefaultWithIssuer("https://mock.issuer");
        OAuth2TokenValidator<Jwt> withAudience = new DelegatingOAuth2TokenValidator<>(withIssuer, new AudienceValidator("mock-audience"));
        ((NimbusJwtDecoder) realNimbusDecoder).setJwtValidator(withAudience);

        org.mockito.Mockito.when(springMockDecoder.decode(org.mockito.ArgumentMatchers.anyString()))
            .thenAnswer(invocation -> {
                String token = invocation.getArgument(0);
                return realNimbusDecoder.decode(token);
            });
    }

    @Autowired
    private MockMvc mockMvc;

    private String generateToken(NimbusJwtEncoder encoder, String issuer, String audience, Instant expiresAt, String scope) {
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer(issuer)
                .audience(List.of(audience))
                .expiresAt(expiresAt)
                .subject("user1")
                .claim("scope", scope)
                .build();
        return encoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
    }

    @Test
    void missingToken_Returns401() throws Exception {
        mockMvc.perform(get("/audit/events"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void malformedToken_Returns401() throws Exception {
        mockMvc.perform(get("/audit/events").header("Authorization", "Bearer invalid-token"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void expiredToken_Returns401() throws Exception {
        String token = generateToken(jwtEncoder, "https://mock.issuer", "mock-audience", Instant.now().minus(1, ChronoUnit.HOURS), "audit:read");
        mockMvc.perform(get("/audit/events").header("Authorization", "Bearer " + token))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void wrongSignature_Returns401() throws Exception {
        String token = generateToken(wrongEncoder, "https://mock.issuer", "mock-audience", Instant.now().plus(1, ChronoUnit.HOURS), "audit:read");
        mockMvc.perform(get("/audit/events").header("Authorization", "Bearer " + token))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void wrongIssuer_Returns401() throws Exception {
        String token = generateToken(jwtEncoder, "https://WRONG.issuer", "mock-audience", Instant.now().plus(1, ChronoUnit.HOURS), "audit:read");
        mockMvc.perform(get("/audit/events").header("Authorization", "Bearer " + token))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void wrongAudience_Returns401() throws Exception {
        String token = generateToken(jwtEncoder, "https://mock.issuer", "WRONG-audience", Instant.now().plus(1, ChronoUnit.HOURS), "audit:read");
        mockMvc.perform(get("/audit/events").header("Authorization", "Bearer " + token))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void validToken_WrongScope_Returns403() throws Exception {
        String token = generateToken(jwtEncoder, "https://mock.issuer", "mock-audience", Instant.now().plus(1, ChronoUnit.HOURS), "audit:wrong");
        mockMvc.perform(get("/audit/events").header("Authorization", "Bearer " + token))
                .andExpect(status().isForbidden());
    }

    @Test
    void validToken_RightScope_Returns200() throws Exception {
        String token = generateToken(jwtEncoder, "https://mock.issuer", "mock-audience", Instant.now().plus(1, ChronoUnit.HOURS), "audit:read");
        mockMvc.perform(get("/audit/events").header("Authorization", "Bearer " + token))
                .andExpect(status().isOk());
    }
}
