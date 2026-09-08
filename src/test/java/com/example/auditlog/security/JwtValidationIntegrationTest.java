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
        "audit.redaction.hmac-secret=test-secret", 
        "DB_URL=jdbc:mysql://localhost:3306/auditdb?useSSL=false&allowPublicKeyRetrieval=true", 
        "DB_USERNAME=root", "DB_PASSWORD=root",
        "OIDC_ISSUER_URI=https://mock.issuer", 
        "audit.security.oauth2.audience=mock-audience", 
        "PROD_ALLOWED_ORIGINS=http://localhost:3000", 
        "audit.signature.key-id=test-key-1", 
        "audit.signature.private-key=MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCYcAMNLx3WHc9xI8rBJKUFNDgEOyxNKnAjGRtX4pCHAQMcOUtehnMMyJo6dTPT+4fhw0V1S2D4szI0QhZoj9bn8e6rpA2uecoZ2UJenCXNFEqZsahkoOHXh+Oi+a0RTNoBmesWFGWQSiMu/QhPLJkBn29eEcu+GYveB1oMWwUXOZj6Fk0DtiiZRoI9T/QwYcUqpJ/LBweY4S/atU5ZvuMWRPEfOyjHEL/Xm6kkfK2/sc/i9FqT1HF0fkNugLo1Bjz7gYloRyUmLbuEdyA3pHVLl2Db6TpEj8HcnpZvBwkO+8s4chXY7P4HVnHErNynXvKRtk01IrY1bq3FKY7Lzr4hAgMBAAECgf9uwPN2oMUMzJvrmBW4Puem4EnSyStm5W6UEanMMNDRRer8lqQsCYONxjJIRt9hJV+UqEvO7PWHvKq9TUb6sYdy/lRqYMeP/OzZ2wBdvRW56wRIpsuyUTHFZvX9c2pLJ4s9npcvc6JXM4ZcnXtsCvsgMra3ojZl6Cm3J6BFWdxZAmENw0iLRKl9aL9Wunrr7K0E8OSlZBy78V9I8YUIoRiHdQ1Cy/Pk53pe+EM9faioBtpd6evo92OXG9b3/+qxWCi2mEtWXPYjxj27bGwA4BI31RKjdO9yEPRcAlQwYPJVVGGPGRDxdg6BeX8vSBME2qg2ol59DBPSQwgmjf1NsgECgYEAyEIIHQ6hq5YvFgot5NTWyX8slLi0R4Dg+W4Z9LPl/Sg2Ur2RXEqwh4V/vkMc7Zd8LXBnrAe/45R0nJK0Fr4lTBgZQ/HjDj5yuRPwXQSqY86fXkQ/keFsVXIqkCmnAM+Cy8OPC+JYm4pN2g5ykPqTR63Lm1R0r9tvui2YjnG7IDECgYEAwt5lzzDhR6roTOQGyET25FlqZnqIwqyR9WwsIqAjCt+IUFFbDZl527oYSu96Ckbr/L6RylENQslUwkdgEJ5u6I0JSw+i/XBaJCaqVeFdD/u5rJxwcBdv8rYzw+8RZNv+5XWam8yQQYBucERL1OVS/sEbcQVEpM/lAMmvFpGQcPECgYAGKQHW4vxWKuiH5QhEYce5qw/UA1qIWI6THa/utxn8D6CcKvitvh5wDMtBLw9Uv7QyMaL+x74/YfG0X07q5C6BiLw+OtKhPYqJ5vMd6WbUaya7352U/zo15q0ogh+BBuEfI4Ti+LOBFWAPtSIRE6Q0MERzIsX0Iuvs7jojJ5x6AQKBgQCKnJl8pH9KdDZjIzvzzqJz0WqO1JBdMVVtZnGKe7ARdulGgGgtJ0N32UqYWvnLP6FzGbcoWzj8jatdulmJ2Lh5cIDwxIGilv13g41cIz8INH1hW7Ha+cDmu1XdBDuyK46Hd3zvX7Yo8YsdDmeGW00K6x9y6FVoinyRb+S8P/SncQKBgQCq4f/996kpehmS9NHeN5R10UgFEdl9l/2nM1MMQWV2oxIc6LInW/ATRCtuGaXfceefBdJ4NPAzBrm8k8I22pVuO6HLNW1Kqpo5wYJ7zFjeplZgp6crVVZg15NI4gQS2PcV4S4zbS1vZ3/FQDWhyB/UXWQqb6XjFj1hPJSRaS0Spg==", "audit.signature.public-key=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmHADDS8d1h3PcSPKwSSlBTQ4BDssTSpwIxkbV+KQhwEDHDlLXoZzDMiaOnUz0/uH4cNFdUtg+LMyNEIWaI/W5/Huq6QNrnnKGdlCXpwlzRRKmbGoZKDh14fjovmtEUzaAZnrFhRlkEojLv0ITyyZAZ9vXhHLvhmL3gdaDFsFFzmY+hZNA7YomUaCPU/0MGHFKqSfywcHmOEv2rVOWb7jFkTxHzsoxxC/15upJHytv7HP4vRak9RxdH5DboC6NQY8+4GJaEclJi27hHcgN6R1S5dg2+k6RI/B3J6WbwcJDvvLOHIV2Oz+B1ZxxKzcp17ykbZNNSK2NW6txSmOy86+IQIDAQAB"
})
@AutoConfigureMockMvc
@ActiveProfiles("prod")
public class JwtValidationIntegrationTest {

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
