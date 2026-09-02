package com.example.auditlog.security;

import com.example.auditlog.config.ProdSecurityConfig;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class ProdCorsWildcardTest {

    @Test
    void prodCors_WithWildcard_ThrowsException() {
        ProdSecurityConfig config = new ProdSecurityConfig();
        ReflectionTestUtils.setField(config, "allowedOrigins", List.of("http://localhost:3000", "*"));
        
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, config::corsConfigurationSource);
        assertTrue(exception.getMessage().contains("strictly prohibited"));
    }
}
