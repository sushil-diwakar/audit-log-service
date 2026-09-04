package com.example.auditlog.service;

import com.example.auditlog.dto.AuditEventRequest;
import com.example.auditlog.dto.AuditEventResponse;
import com.example.auditlog.entity.AuditRecord;
import com.example.auditlog.repository.AuditRecordRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

import org.springframework.test.context.TestPropertySource;

@SpringBootTest(properties = {"DEV_USER=test", "DEV_PASSWORD=test", "audit.signature.key-id=test-key-1", "audit.signature.private-key=MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCYcAMNLx3WHc9xI8rBJKUFNDgEOyxNKnAjGRtX4pCHAQMcOUtehnMMyJo6dTPT+4fhw0V1S2D4szI0QhZoj9bn8e6rpA2uecoZ2UJenCXNFEqZsahkoOHXh+Oi+a0RTNoBmesWFGWQSiMu/QhPLJkBn29eEcu+GYveB1oMWwUXOZj6Fk0DtiiZRoI9T/QwYcUqpJ/LBweY4S/atU5ZvuMWRPEfOyjHEL/Xm6kkfK2/sc/i9FqT1HF0fkNugLo1Bjz7gYloRyUmLbuEdyA3pHVLl2Db6TpEj8HcnpZvBwkO+8s4chXY7P4HVnHErNynXvKRtk01IrY1bq3FKY7Lzr4hAgMBAAECgf9uwPN2oMUMzJvrmBW4Puem4EnSyStm5W6UEanMMNDRRer8lqQsCYONxjJIRt9hJV+UqEvO7PWHvKq9TUb6sYdy/lRqYMeP/OzZ2wBdvRW56wRIpsuyUTHFZvX9c2pLJ4s9npcvc6JXM4ZcnXtsCvsgMra3ojZl6Cm3J6BFWdxZAmENw0iLRKl9aL9Wunrr7K0E8OSlZBy78V9I8YUIoRiHdQ1Cy/Pk53pe+EM9faioBtpd6evo92OXG9b3/+qxWCi2mEtWXPYjxj27bGwA4BI31RKjdO9yEPRcAlQwYPJVVGGPGRDxdg6BeX8vSBME2qg2ol59DBPSQwgmjf1NsgECgYEAyEIIHQ6hq5YvFgot5NTWyX8slLi0R4Dg+W4Z9LPl/Sg2Ur2RXEqwh4V/vkMc7Zd8LXBnrAe/45R0nJK0Fr4lTBgZQ/HjDj5yuRPwXQSqY86fXkQ/keFsVXIqkCmnAM+Cy8OPC+JYm4pN2g5ykPqTR63Lm1R0r9tvui2YjnG7IDECgYEAwt5lzzDhR6roTOQGyET25FlqZnqIwqyR9WwsIqAjCt+IUFFbDZl527oYSu96Ckbr/L6RylENQslUwkdgEJ5u6I0JSw+i/XBaJCaqVeFdD/u5rJxwcBdv8rYzw+8RZNv+5XWam8yQQYBucERL1OVS/sEbcQVEpM/lAMmvFpGQcPECgYAGKQHW4vxWKuiH5QhEYce5qw/UA1qIWI6THa/utxn8D6CcKvitvh5wDMtBLw9Uv7QyMaL+x74/YfG0X07q5C6BiLw+OtKhPYqJ5vMd6WbUaya7352U/zo15q0ogh+BBuEfI4Ti+LOBFWAPtSIRE6Q0MERzIsX0Iuvs7jojJ5x6AQKBgQCKnJl8pH9KdDZjIzvzzqJz0WqO1JBdMVVtZnGKe7ARdulGgGgtJ0N32UqYWvnLP6FzGbcoWzj8jatdulmJ2Lh5cIDwxIGilv13g41cIz8INH1hW7Ha+cDmu1XdBDuyK46Hd3zvX7Yo8YsdDmeGW00K6x9y6FVoinyRb+S8P/SncQKBgQCq4f/996kpehmS9NHeN5R10UgFEdl9l/2nM1MMQWV2oxIc6LInW/ATRCtuGaXfceefBdJ4NPAzBrm8k8I22pVuO6HLNW1Kqpo5wYJ7zFjeplZgp6crVVZg15NI4gQS2PcV4S4zbS1vZ3/FQDWhyB/UXWQqb6XjFj1hPJSRaS0Spg==", "audit.signature.public-key=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmHADDS8d1h3PcSPKwSSlBTQ4BDssTSpwIxkbV+KQhwEDHDlLXoZzDMiaOnUz0/uH4cNFdUtg+LMyNEIWaI/W5/Huq6QNrnnKGdlCXpwlzRRKmbGoZKDh14fjovmtEUzaAZnrFhRlkEojLv0ITyyZAZ9vXhHLvhmL3gdaDFsFFzmY+hZNA7YomUaCPU/0MGHFKqSfywcHmOEv2rVOWb7jFkTxHzsoxxC/15upJHytv7HP4vRak9RxdH5DboC6NQY8+4GJaEclJi27hHcgN6R1S5dg2+k6RI/B3J6WbwcJDvvLOHIV2Oz+B1ZxxKzcp17ykbZNNSK2NW6txSmOy86+IQIDAQAB"})
@ActiveProfiles("dev")
@TestPropertySource(properties = "spring.jpa.hibernate.ddl-auto=create-drop")
class HashChainIntegrationTest {

    @Autowired
    private AuditService auditService;

    @Autowired
    private AuditRecordRepository repository;

    @Autowired
    private ObjectMapper mapper;

    @Autowired
    private HashService hashService;

    @BeforeEach
    void setUp() {
        repository.deleteAll();
    }

    private AuditEventRequest createRequest(String actor) throws Exception {
        AuditEventRequest req = new AuditEventRequest();
        req.setEventType("TEST_EVENT");
        req.setActorId(actor);
        req.setResourceType("SYS");
        req.setResourceId("1");
        req.setPayload(mapper.readTree("{\"action\":\"test\"}"));
        // Use fixed precision to avoid MySQL nanosecond truncation mismatch
        req.setTimestamp(Instant.now().truncatedTo(java.time.temporal.ChronoUnit.MILLIS));
        return req;
    }

    @Test
    void testGenesisAndChaining() throws Exception {
        // 1. First record uses GENESIS
        AuditEventResponse res1 = auditService.createAuditEvent(createRequest("actor-1"));
        AuditRecord rec1 = repository.findById(res1.getId()).orElseThrow();
        
        assertThat(rec1.getPreviousHash()).isEqualTo(AuditService.GENESIS_HASH);
        assertThat(rec1.getRecordHash()).isNotNull();

        // 2. Second record references the first record's hash
        AuditEventResponse res2 = auditService.createAuditEvent(createRequest("actor-2"));
        AuditRecord rec2 = repository.findById(res2.getId()).orElseThrow();
        
        assertThat(rec2.getPreviousHash()).isEqualTo(rec1.getRecordHash());

        // 3. Third record references the second record's hash
        AuditEventResponse res3 = auditService.createAuditEvent(createRequest("actor-3"));
        AuditRecord rec3 = repository.findById(res3.getId()).orElseThrow();
        
        assertThat(rec3.getPreviousHash()).isEqualTo(rec2.getRecordHash());
    }

    @Test
    void testRecordHashesAreDeterministicAndTamperEvident() throws Exception {
        auditService.createAuditEvent(createRequest("actor-1"));
        AuditRecord rec1 = repository.findAll().getFirst();

        String originalContentHash = hashService.calculateContentHash(rec1);
        String originalRecordHash = hashService.calculateRecordHash(originalContentHash, rec1.getPreviousHash());

        assertThat(rec1.getRecordHash()).isEqualTo(originalRecordHash);

        // Tamper with the record
        rec1.setActorId("hacker");
        String tamperedContentHash = hashService.calculateContentHash(rec1);

        assertThat(tamperedContentHash).isNotEqualTo(originalContentHash);
        
        String tamperedRecordHash = hashService.calculateRecordHash(tamperedContentHash, rec1.getPreviousHash());
        assertThat(tamperedRecordHash).isNotEqualTo(originalRecordHash);
    }

    @Test
    void testConcurrencySafeguardWithUniqueConstraint() throws InterruptedException {
        int threadCount = 3;
        ExecutorService executor = Executors.newFixedThreadPool(threadCount);
        CountDownLatch latch = new CountDownLatch(threadCount);
        
        AtomicInteger successCount = new AtomicInteger(0);
        AtomicInteger failureCount = new AtomicInteger(0);

        for (int i = 0; i < threadCount; i++) {
            final int index = i;
            executor.submit(() -> {
                try {
                    auditService.createAuditEvent(createRequest("concurrent-actor-" + index));
                    successCount.incrementAndGet();
                } catch (Exception e) {
                    failureCount.incrementAndGet();
                } finally {
                    latch.countDown();
                }
            });
        }

        latch.await();
        
        // Assert that a strict chain was formed for whatever managed to save.
        List<AuditRecord> records = repository.findAll();
        assertThat(records).isNotEmpty();
        
        // Exactly one genesis
        long genesisCount = records.stream().filter(r -> AuditService.GENESIS_HASH.equals(r.getPreviousHash())).count();
        assertThat(genesisCount).isEqualTo(1);

        // Reconstruct the chain by tracing previousHash links
        String currentHash = AuditService.GENESIS_HASH;
        int chainedCount = 0;
        
        while (true) {
            final String targetPrev = currentHash;
            AuditRecord next = records.stream()
                .filter(r -> r.getPreviousHash().equals(targetPrev))
                .findFirst()
                .orElse(null);
                
            if (next == null) break;
            
            chainedCount++;
            currentHash = next.getRecordHash();
        }
        
        // Every saved record must belong to this single linear chain, proving no forks
        assertThat(chainedCount).isEqualTo(records.size());
        
        // Verify exactly one chain head using the repository query
        AuditRecord currentHead = repository.findCurrentChainHead().orElse(null);
        assertThat(currentHead).isNotNull();
        assertThat(currentHead.getRecordHash()).isEqualTo(currentHash); // The final hash traced
    }

    @Test
    void testAppendOrderIsIndependentOfEventTimestamp() throws Exception {
        // Create Request A with a FUTURE timestamp (T2)
        AuditEventRequest reqA = createRequest("actor-A");
        reqA.setTimestamp(Instant.now().plusSeconds(3600).truncatedTo(java.time.temporal.ChronoUnit.MILLIS));
        AuditEventResponse resA = auditService.createAuditEvent(reqA);
        
        // Create Request B with a PAST timestamp (T1) where T1 < T2
        AuditEventRequest reqB = createRequest("actor-B");
        reqB.setTimestamp(Instant.now().minusSeconds(3600).truncatedTo(java.time.temporal.ChronoUnit.MILLIS));
        AuditEventResponse resB = auditService.createAuditEvent(reqB);
        
        AuditRecord recA = repository.findById(resA.getId()).orElseThrow();
        AuditRecord recB = repository.findById(resB.getId()).orElseThrow();
        
        // A was appended first, so it should be GENESIS
        assertThat(recA.getPreviousHash()).isEqualTo(AuditService.GENESIS_HASH);
        
        // B was appended second, so it MUST point to A, despite B's timestamp being EARLIER than A's
        assertThat(recB.getPreviousHash()).isEqualTo(recA.getRecordHash());
        
        // Querying the chain head should return B
        AuditRecord head = repository.findCurrentChainHead().orElseThrow();
        assertThat(head.getId()).isEqualTo(recB.getId());
    }
}
