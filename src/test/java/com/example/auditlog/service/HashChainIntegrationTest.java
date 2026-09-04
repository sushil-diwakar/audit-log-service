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

@SpringBootTest(properties = {"DEV_USER=test", "DEV_PASSWORD=test"})
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
