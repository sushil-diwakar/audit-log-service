package com.example.auditlog;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.SQLException;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SpringBootTest
class AuditLogApplicationTests {

    @Autowired
    private DataSource dataSource;

    @Test
    void contextLoads() {
        // Verifies that Spring Boot application context loads successfully
    }

    @Test
    void testDatabaseConnection() throws SQLException {
        assertNotNull(dataSource, "DataSource bean should be configured and injected");
        try (Connection connection = dataSource.getConnection()) {
            assertNotNull(connection, "Database connection should not be null");
            assertTrue(connection.isValid(2), "Database connection should be valid");
        }
    }
}
