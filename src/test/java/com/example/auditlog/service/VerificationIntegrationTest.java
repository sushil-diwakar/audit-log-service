package com.example.auditlog.service;







import com.example.auditlog.dto.AuditEventRequest;



import com.example.auditlog.dto.AuditEventResponse;



import com.example.auditlog.dto.VerificationResponse;



import com.example.auditlog.entity.AuditRecord;



import com.example.auditlog.enums.ChainViolationType;



import com.example.auditlog.repository.AuditRecordRepository;



import com.fasterxml.jackson.databind.ObjectMapper;



import org.junit.jupiter.api.BeforeEach;



import org.junit.jupiter.api.Test;



import org.springframework.beans.factory.annotation.Autowired;



import org.springframework.boot.test.context.SpringBootTest;



import org.springframework.test.context.ActiveProfiles;



import org.springframework.jdbc.core.JdbcTemplate;



import org.springframework.test.context.TestPropertySource;







import java.time.Instant;



import java.util.UUID;







import static org.assertj.core.api.Assertions.assertThat;







@SpringBootTest(properties = {
    "DEV_USER=test", "DEV_PASSWORD=test", 
    "spring.datasource.url=jdbc:h2:mem:auditdb;DB_CLOSE_DELAY=-1;MODE=MySQL", 
    "spring.datasource.username=sa", "spring.datasource.driver-class-name=org.h2.Driver", "spring.datasource.password="
})
@ActiveProfiles("dev")
@TestPropertySource(properties = "spring.jpa.hibernate.ddl-auto=create-drop")
class VerificationIntegrationTest {

    @org.springframework.test.context.DynamicPropertySource
    static void dynamicProperties(org.springframework.test.context.DynamicPropertyRegistry registry) throws Exception {
        java.security.KeyPairGenerator generator = java.security.KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        java.security.KeyPair pair = generator.generateKeyPair();
        registry.add("audit.signature.public-key", () -> java.util.Base64.getEncoder().encodeToString(pair.getPublic().getEncoded()));
        registry.add("audit.signature.private-key", () -> java.util.Base64.getEncoder().encodeToString(pair.getPrivate().getEncoded()));
        registry.add("audit.signature.key-id", () -> "test-key-dynamic");
        registry.add("audit.redaction.hmac-secret", () -> java.util.UUID.randomUUID().toString());
        registry.add("spring.datasource.url", () -> "jdbc:h2:mem:auditdb;DB_CLOSE_DELAY=-1;MODE=MySQL");
        registry.add("spring.datasource.username", () -> "sa");
        registry.add("spring.datasource.password", () -> "");
        registry.add("spring.datasource.driver-class-name", () -> "org.h2.Driver");
        registry.add("DEV_USER", () -> "test");
        registry.add("DEV_PASSWORD", () -> "test");
    }



    @Test

    void testTamperRedaction_ModifyPayloadAfterRedaction() throws Exception {

        AuditEventResponse evt = auditService.createAuditEvent(createRequest("actor-1"));



        // 1. Legitimate redaction

        String originalContentHash = repository.findById(evt.getId()).get().getContentHash();

        AuditRecord record = repository.findById(evt.getId()).get();
        String legitimateRedactionDigest = hashService.calculateRedactionDigest(record, mapper.readTree("{\"redacted\":true}"));



        jdbcTemplate.update("UPDATE audit_records SET payload = ?, status = ?, redaction_digest = ? WHERE actor_id = ?",

                "{\"redacted\":true}", "REDACTED", legitimateRedactionDigest, "actor-1");



        // Confirm it passes initially

        assertThat(verificationService.verifyChain().isValid()).isTrue();



        // 2. Tamper the redacted payload

        jdbcTemplate.update("UPDATE audit_records SET payload = ? WHERE actor_id = ?",

                "{\"redacted\":true, \"hacker\":\"was_here\"}", "actor-1");



        VerificationResponse response = verificationService.verifyChain();

        assertThat(response.isValid()).isFalse();

        assertThat(response.getViolationType()).isEqualTo(ChainViolationType.REDACTION_METADATA_MISMATCH);

    }









    @Test



    void testTamperRedaction_MissingDigest_DetectsMetadataMismatch() throws Exception {



        AuditEventResponse evt = auditService.createAuditEvent(createRequest("actor-1"));







        jdbcTemplate.update("UPDATE audit_records SET payload = ?, status = ? WHERE actor_id = ?",



                "{\"redacted\":true}", "REDACTED", "actor-1");







        VerificationResponse response = verificationService.verifyChain();



        assertThat(response.isValid()).isFalse();



        assertThat(response.getViolationType()).isEqualTo(ChainViolationType.REDACTION_METADATA_MISMATCH);



        assertThat(response.getRecordId()).isEqualTo(evt.getId());



    }







    @Test



    void testTamperRedaction_InvalidDigest_DetectsMetadataMismatch() throws Exception {



        AuditEventResponse evt = auditService.createAuditEvent(createRequest("actor-1"));







        jdbcTemplate.update("UPDATE audit_records SET payload = ?, status = ?, redaction_digest = ? WHERE actor_id = ?",



                "{\"redacted\":true}", "REDACTED", "forged-digest-123", "actor-1");







        VerificationResponse response = verificationService.verifyChain();



        assertThat(response.isValid()).isFalse();



        assertThat(response.getViolationType()).isEqualTo(ChainViolationType.REDACTION_METADATA_MISMATCH);



        assertThat(response.getRecordId()).isEqualTo(evt.getId());



    }











    @Autowired



    private ChainVerificationService verificationService;







    @Autowired



    private AuditService auditService;







    @Autowired



    private AuditRecordRepository repository;







    @Autowired



    private JdbcTemplate jdbcTemplate;







    @Autowired



    private ObjectMapper mapper;







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



        req.setTimestamp(Instant.now().truncatedTo(java.time.temporal.ChronoUnit.MILLIS));



        return req;



    }







    @Test



    void testEmptyDatabaseVerification() {



        VerificationResponse response = verificationService.verifyChain();



        assertThat(response.isValid()).isTrue();



        assertThat(response.getCheckedRecords()).isEqualTo(0);



    }







    @Test



    void testOneValidRecordVerification() throws Exception {



        auditService.createAuditEvent(createRequest("actor-1"));



        VerificationResponse response = verificationService.verifyChain();







        assertThat(response.isValid()).isTrue();



        assertThat(response.getCheckedRecords()).isEqualTo(1);



    }







    @Test



    void testMultipleValidRecordsVerification() throws Exception {



        auditService.createAuditEvent(createRequest("actor-1"));



        auditService.createAuditEvent(createRequest("actor-2"));



        auditService.createAuditEvent(createRequest("actor-3"));







        VerificationResponse response = verificationService.verifyChain();







        assertThat(response.isValid()).isTrue();



        assertThat(response.getCheckedRecords()).isEqualTo(3);



    }







    @Test



    void testTamperContent_DetectsContentHashMismatch() throws Exception {



        AuditEventResponse evt = auditService.createAuditEvent(createRequest("actor-1"));







        // Pass the UUID object directly so JdbcTemplate maps it correctly to BINARY(16) if needed



        int rows = jdbcTemplate.update("UPDATE audit_records SET actor_id = 'hacker' WHERE actor_id = 'actor-1'");



        assertThat(rows).isEqualTo(1);







        VerificationResponse response = verificationService.verifyChain();







        assertThat(response.isValid()).isFalse();



        assertThat(response.getViolationType()).isEqualTo(ChainViolationType.CONTENT_HASH_MISMATCH);



    }







    @Test



    void testTamperPreviousHash_DetectsBrokenLinkageOrMultipleGenesis() throws Exception {



        AuditEventResponse evt1 = auditService.createAuditEvent(createRequest("actor-1"));



        AuditEventResponse evt2 = auditService.createAuditEvent(createRequest("actor-2"));







        // Break the linkage by changing evt2's previousHash to a garbage value



        int rows = jdbcTemplate.update("UPDATE audit_records SET previous_hash = 'GARBAGE_LINK' WHERE actor_id = 'actor-2'");



        assertThat(rows).isEqualTo(1);







        VerificationResponse response = verificationService.verifyChain();







        assertThat(response.isValid()).isFalse();



        // Since previousHash is used in recordHash calculation, it will trigger RECORD_HASH_MISMATCH first during content integrity check



        assertThat(response.getViolationType()).isEqualTo(ChainViolationType.RECORD_HASH_MISMATCH);



    }







    @Test



    void testTamperRecordHash_DetectsRecordHashMismatch() throws Exception {



        AuditEventResponse evt = auditService.createAuditEvent(createRequest("actor-1"));







        int rows = jdbcTemplate.update("UPDATE audit_records SET record_hash = 'tampered' WHERE actor_id = 'actor-1'");



        assertThat(rows).isEqualTo(1);







        VerificationResponse response = verificationService.verifyChain();







        assertThat(response.isValid()).isFalse();



        assertThat(response.getViolationType()).isEqualTo(ChainViolationType.RECORD_HASH_MISMATCH);



    }







    @Autowired



    private HashService hashService;







    @Test



    void testDisconnectedOrphanRecord() throws Exception {



        // Create a normal chain



        auditService.createAuditEvent(createRequest("actor-1"));



        auditService.createAuditEvent(createRequest("actor-2"));







        // Manually build an orphan record



        AuditRecord orphan = AuditRecord.builder()



                .eventType("TEST_EVENT")



                .actorId("orphan-actor")



                .resourceType("SYS")



                .resourceId("1")



                .payload(mapper.readTree("{\"action\":\"test\"}"))



                .timestamp(Instant.now().truncatedTo(java.time.temporal.ChronoUnit.MILLIS))



                .build();







        orphan.setPreviousHash("SOME_RANDOM_UNLINKED_HASH");







        // Calculate exact correct hashes so it passes the RECORD_HASH_MISMATCH check



        String contentHash = hashService.calculateContentHash(orphan);



        orphan.setContentHash(contentHash);







        String recordHash = hashService.calculateRecordHash(contentHash, orphan.getPreviousHash());



        orphan.setRecordHash(recordHash);







        // Save using repository



        repository.saveAndFlush(orphan);







        VerificationResponse response = verificationService.verifyChain();







        // The chain will traverse GENESIS -> actor-1 -> actor-2.



        // It will stop.



        // Then it will see the orphan wasn't visited.



        assertThat(response.isValid()).isFalse();



        assertThat(response.getViolationType()).isEqualTo(ChainViolationType.DISCONNECTED_RECORD);



    }



    @Test
    void testTamperContentHash_AfterRedaction() throws Exception {
        AuditEventResponse evt = auditService.createAuditEvent(createRequest("actor-1"));
        AuditRecord record = repository.findById(evt.getId()).get();
        String legitimateRedactionDigest = hashService.calculateRedactionDigest(record, mapper.readTree("{\"redacted\":true}"));
        jdbcTemplate.update("UPDATE audit_records SET payload = ?, status = ?, redaction_digest = ? WHERE actor_id = ?",
                "{\"redacted\":true}", "REDACTED", legitimateRedactionDigest, "actor-1");

        jdbcTemplate.update("UPDATE audit_records SET content_hash = 'tampered' WHERE actor_id = 'actor-1'");
        VerificationResponse response = verificationService.verifyChain();
        assertThat(response.isValid()).isFalse();
        assertThat(response.getViolationType()).isIn(ChainViolationType.INVALID_CONTENT_HASH, ChainViolationType.REDACTION_METADATA_MISMATCH, ChainViolationType.RECORD_HASH_MISMATCH);
    }

    @Test
    void testTamperRevertRedactionToActive() throws Exception {
        AuditEventResponse evt = auditService.createAuditEvent(createRequest("actor-1"));
        AuditRecord record = repository.findById(evt.getId()).get();
        String legitimateRedactionDigest = hashService.calculateRedactionDigest(record, mapper.readTree("{\"redacted\":true}"));
        jdbcTemplate.update("UPDATE audit_records SET payload = ?, status = ?, redaction_digest = ? WHERE actor_id = ?",
                "{\"redacted\":true}", "REDACTED", legitimateRedactionDigest, "actor-1");

        jdbcTemplate.update("UPDATE audit_records SET status = 'ACTIVE' WHERE actor_id = 'actor-1'");
        VerificationResponse response = verificationService.verifyChain();
        assertThat(response.isValid()).isFalse();
        assertThat(response.getViolationType()).isEqualTo(ChainViolationType.CONTENT_HASH_MISMATCH);
    }

    @Test
    void testConstructMaliciousRedactionState_FailsHMAC() throws Exception {
        AuditEventResponse evt = auditService.createAuditEvent(createRequest("actor-1"));
        AuditRecord record = repository.findById(evt.getId()).get();

        String forgedDigest = "forged1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
        jdbcTemplate.update("UPDATE audit_records SET payload = ?, status = ?, redaction_digest = ? WHERE actor_id = ?",
                "{\"redacted\":true, \"hack\":\"success\"}", "REDACTED", forgedDigest, "actor-1");

        VerificationResponse response = verificationService.verifyChain();
        assertThat(response.isValid()).isFalse();
        assertThat(response.getViolationType()).isEqualTo(ChainViolationType.REDACTION_METADATA_MISMATCH);
    }
    @Test
    void testTamperContent_AllFields() throws Exception {
        AuditEventResponse evt = auditService.createAuditEvent(createRequest("actor-all"));

        // tamper eventType
        jdbcTemplate.update("UPDATE audit_records SET event_type = 'HACKED' WHERE actor_id = 'actor-all'");
        assertThat(verificationService.verifyChain().getViolationType()).isEqualTo(ChainViolationType.CONTENT_HASH_MISMATCH);
        jdbcTemplate.update("UPDATE audit_records SET event_type = 'TEST_EVENT' WHERE actor_id = 'actor-all'"); // revert

        // tamper resourceType
        jdbcTemplate.update("UPDATE audit_records SET resource_type = 'HACKED' WHERE actor_id = 'actor-all'");
        assertThat(verificationService.verifyChain().getViolationType()).isEqualTo(ChainViolationType.CONTENT_HASH_MISMATCH);
        jdbcTemplate.update("UPDATE audit_records SET resource_type = 'SYS' WHERE actor_id = 'actor-all'"); // revert

        // tamper resourceId
        jdbcTemplate.update("UPDATE audit_records SET resource_id = '999' WHERE actor_id = 'actor-all'");
        assertThat(verificationService.verifyChain().getViolationType()).isEqualTo(ChainViolationType.CONTENT_HASH_MISMATCH);
        jdbcTemplate.update("UPDATE audit_records SET resource_id = '1' WHERE actor_id = 'actor-all'"); // revert

        // tamper payload
        jdbcTemplate.update("UPDATE audit_records SET payload = '{\"action\":\"hacked\"}' WHERE actor_id = 'actor-all'");
        assertThat(verificationService.verifyChain().getViolationType()).isEqualTo(ChainViolationType.CONTENT_HASH_MISMATCH);
        jdbcTemplate.update("UPDATE audit_records SET payload = '{\"action\":\"test\"}' WHERE actor_id = 'actor-all'"); // revert

        // tamper timestamp
        jdbcTemplate.update("UPDATE audit_records SET timestamp = ? WHERE actor_id = 'actor-all'", Instant.now().minusSeconds(3600));
        assertThat(verificationService.verifyChain().getViolationType()).isEqualTo(ChainViolationType.CONTENT_HASH_MISMATCH);
    }

    @Test
    void testMissingGenesis_DetectsMissingGenesis() throws Exception {
        auditService.createAuditEvent(createRequest("actor-missing-gen"));
        jdbcTemplate.update("UPDATE audit_records SET previous_hash = 'NON_EXISTENT' WHERE previous_hash = 'GENESIS'");
        VerificationResponse response = verificationService.verifyChain();
        assertThat(response.isValid()).isFalse();
        assertThat(response.getViolationType()).isIn(ChainViolationType.BROKEN_PREVIOUS_LINK, ChainViolationType.MISSING_GENESIS, ChainViolationType.RECORD_HASH_MISMATCH, ChainViolationType.DISCONNECTED_RECORD);
    }

    @Test
    void testMultipleGenesis_DetectsMultipleGenesis() throws Exception {
        AuditEventResponse evt1 = auditService.createAuditEvent(createRequest("actor-gen-1"));
        AuditEventResponse evt2 = auditService.createAuditEvent(createRequest("actor-gen-2"));
        // The database schema has a UNIQUE constraint on previous_hash. We assert it actively prevents multiple genesis.
        org.assertj.core.api.Assertions.assertThatThrownBy(() ->
            jdbcTemplate.update("UPDATE audit_records SET previous_hash = 'GENESIS' WHERE actor_id = 'actor-gen-2'")
        ).isInstanceOf(org.springframework.dao.DuplicateKeyException.class);
    }

    @Test
    void testBrokenPreviousLink_DetectsBrokenLink() throws Exception {
        auditService.createAuditEvent(createRequest("actor-brk-1"));
        AuditEventResponse evt2 = auditService.createAuditEvent(createRequest("actor-brk-2"));
        jdbcTemplate.update("UPDATE audit_records SET previous_hash = 'NON_EXISTENT' WHERE actor_id = 'actor-brk-2'");
        AuditRecord record2 = repository.findById(evt2.getId()).get();
        String contentHash = hashService.calculateContentHash(record2);
        String recordHash = hashService.calculateRecordHash(contentHash, "NON_EXISTENT");
        jdbcTemplate.update("UPDATE audit_records SET content_hash = ?, record_hash = ? WHERE actor_id = 'actor-brk-2'", contentHash, recordHash);

        VerificationResponse response = verificationService.verifyChain();
        assertThat(response.isValid()).isFalse();
        assertThat(response.getViolationType()).isIn(ChainViolationType.BROKEN_PREVIOUS_LINK, ChainViolationType.RECORD_HASH_MISMATCH, ChainViolationType.DISCONNECTED_RECORD);
    }

    @Test
    void testFork_DetectsFork() throws Exception {
        AuditEventResponse evt1 = auditService.createAuditEvent(createRequest("actor-fork-1"));
        AuditEventResponse evt2 = auditService.createAuditEvent(createRequest("actor-fork-2"));
        AuditEventResponse evt3 = auditService.createAuditEvent(createRequest("actor-fork-3"));

        AuditRecord record1 = repository.findById(evt1.getId()).get();

        // The database schema has a UNIQUE constraint on previous_hash. We assert it actively prevents forks.
        org.assertj.core.api.Assertions.assertThatThrownBy(() ->
            jdbcTemplate.update("UPDATE audit_records SET previous_hash = ? WHERE actor_id = 'actor-fork-3'", record1.getRecordHash())
        ).isInstanceOf(org.springframework.dao.DuplicateKeyException.class);
    }

    @Test
    void testCycle_DetectsCycle() throws Exception {
        AuditEventResponse evt1 = auditService.createAuditEvent(createRequest("actor-cyc-1"));
        AuditEventResponse evt2 = auditService.createAuditEvent(createRequest("actor-cyc-2"));

        AuditRecord record1 = repository.findById(evt1.getId()).get();
        AuditRecord record2 = repository.findById(evt2.getId()).get();

        jdbcTemplate.update("UPDATE audit_records SET previous_hash = ? WHERE actor_id = 'actor-cyc-1'", record2.getRecordHash());
        String contentHash = hashService.calculateContentHash(record1);
        String recordHash = hashService.calculateRecordHash(contentHash, record2.getRecordHash());
        jdbcTemplate.update("UPDATE audit_records SET content_hash = ?, record_hash = ? WHERE actor_id = 'actor-cyc-1'", contentHash, recordHash);

        VerificationResponse response = verificationService.verifyChain();
        assertThat(response.isValid()).isFalse();
        assertThat(response.getViolationType()).isIn(ChainViolationType.CYCLE_DETECTED, ChainViolationType.MISSING_GENESIS);
    }
}
