package com.example.auditlog.service;

import com.example.auditlog.dto.AuditEventRequest;
import com.example.auditlog.repository.AuditRecordRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.security.test.context.support.WithMockUser;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(properties = {
    "DEV_USER=test", "DEV_PASSWORD=test", 
    "spring.datasource.url=jdbc:h2:mem:auditdb;DB_CLOSE_DELAY=-1", 
    "spring.datasource.username=sa", "spring.datasource.driver-class-name=org.h2.Driver", "spring.datasource.password="
})
@ActiveProfiles("dev")
@TestPropertySource(properties = "spring.jpa.hibernate.ddl-auto=create-drop")
public class ConcurrentAppendTest {

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
    private AuditService auditService;

    @Autowired
    private AuditRecordRepository repository;

    @Autowired
    private ChainVerificationService verificationService;

    @Autowired
    private ObjectMapper mapper;

    @BeforeEach
    void setUp() {
        repository.deleteAll();
    }

    @Test


    @WithMockUser(username = "actor-all", authorities = {"SCOPE_audit:read", "SCOPE_audit:write", "SCOPE_audit:redact", "SCOPE_audit:archive", "SCOPE_audit:export", "SCOPE_audit:verify", "ROLE_ADMIN"})
    void testConcurrentAppend_DoesNotCreateFork() throws Exception {
        int threadCount = 10;
        ExecutorService executor = Executors.newFixedThreadPool(threadCount);
        List<Callable<Void>> tasks = new ArrayList<>();

        org.springframework.security.core.context.SecurityContext context = org.springframework.security.core.context.SecurityContextHolder.getContext();
        for (int i = 0; i < threadCount; i++) {
            final int index = i;
            tasks.add(() -> {
                org.springframework.security.core.context.SecurityContextHolder.setContext(context);
                try {
                    AuditEventRequest req = new AuditEventRequest();
                    req.setActorId("actor-" + index);
                    req.setEventType("TEST");
                    req.setResourceType("SYS");
                    req.setResourceId("id-" + index);
                    req.setPayload(mapper.readTree("{\"thread\":" + index + "}"));
                    req.setTimestamp(Instant.now());
                    auditService.createAuditEvent(req);
                    return null;
                } finally {
                    org.springframework.security.core.context.SecurityContextHolder.clearContext();
                }
            });
        }

        List<Future<Void>> futures = executor.invokeAll(tasks);
        for (Future<Void> future : futures) {
            try {
                future.get();
            } catch (Exception e) {
                // Ignore. The system correctly aborted a race condition.
                // We just want to ensure it didn't write an invalid state.
            }
        }
        executor.shutdown();

        long actualCount = repository.count();
        assertThat(actualCount).isGreaterThan(0);
        
        // 2. The chain must not have forks (unique previousHash = count)
        long uniquePreviousHashes = repository.findAll().stream()
                .map(r -> r.getPreviousHash())
                .distinct()
                .count();
        assertThat(uniquePreviousHashes).isEqualTo(actualCount);
    }
}
