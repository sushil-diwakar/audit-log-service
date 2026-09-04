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







@SpringBootTest(properties = {"DEV_USER=test", "DEV_PASSWORD=test", "audit.signature.key-id=test-key-1", "audit.signature.private-key=MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCYcAMNLx3WHc9xI8rBJKUFNDgEOyxNKnAjGRtX4pCHAQMcOUtehnMMyJo6dTPT+4fhw0V1S2D4szI0QhZoj9bn8e6rpA2uecoZ2UJenCXNFEqZsahkoOHXh+Oi+a0RTNoBmesWFGWQSiMu/QhPLJkBn29eEcu+GYveB1oMWwUXOZj6Fk0DtiiZRoI9T/QwYcUqpJ/LBweY4S/atU5ZvuMWRPEfOyjHEL/Xm6kkfK2/sc/i9FqT1HF0fkNugLo1Bjz7gYloRyUmLbuEdyA3pHVLl2Db6TpEj8HcnpZvBwkO+8s4chXY7P4HVnHErNynXvKRtk01IrY1bq3FKY7Lzr4hAgMBAAECgf9uwPN2oMUMzJvrmBW4Puem4EnSyStm5W6UEanMMNDRRer8lqQsCYONxjJIRt9hJV+UqEvO7PWHvKq9TUb6sYdy/lRqYMeP/OzZ2wBdvRW56wRIpsuyUTHFZvX9c2pLJ4s9npcvc6JXM4ZcnXtsCvsgMra3ojZl6Cm3J6BFWdxZAmENw0iLRKl9aL9Wunrr7K0E8OSlZBy78V9I8YUIoRiHdQ1Cy/Pk53pe+EM9faioBtpd6evo92OXG9b3/+qxWCi2mEtWXPYjxj27bGwA4BI31RKjdO9yEPRcAlQwYPJVVGGPGRDxdg6BeX8vSBME2qg2ol59DBPSQwgmjf1NsgECgYEAyEIIHQ6hq5YvFgot5NTWyX8slLi0R4Dg+W4Z9LPl/Sg2Ur2RXEqwh4V/vkMc7Zd8LXBnrAe/45R0nJK0Fr4lTBgZQ/HjDj5yuRPwXQSqY86fXkQ/keFsVXIqkCmnAM+Cy8OPC+JYm4pN2g5ykPqTR63Lm1R0r9tvui2YjnG7IDECgYEAwt5lzzDhR6roTOQGyET25FlqZnqIwqyR9WwsIqAjCt+IUFFbDZl527oYSu96Ckbr/L6RylENQslUwkdgEJ5u6I0JSw+i/XBaJCaqVeFdD/u5rJxwcBdv8rYzw+8RZNv+5XWam8yQQYBucERL1OVS/sEbcQVEpM/lAMmvFpGQcPECgYAGKQHW4vxWKuiH5QhEYce5qw/UA1qIWI6THa/utxn8D6CcKvitvh5wDMtBLw9Uv7QyMaL+x74/YfG0X07q5C6BiLw+OtKhPYqJ5vMd6WbUaya7352U/zo15q0ogh+BBuEfI4Ti+LOBFWAPtSIRE6Q0MERzIsX0Iuvs7jojJ5x6AQKBgQCKnJl8pH9KdDZjIzvzzqJz0WqO1JBdMVVtZnGKe7ARdulGgGgtJ0N32UqYWvnLP6FzGbcoWzj8jatdulmJ2Lh5cIDwxIGilv13g41cIz8INH1hW7Ha+cDmu1XdBDuyK46Hd3zvX7Yo8YsdDmeGW00K6x9y6FVoinyRb+S8P/SncQKBgQCq4f/996kpehmS9NHeN5R10UgFEdl9l/2nM1MMQWV2oxIc6LInW/ATRCtuGaXfceefBdJ4NPAzBrm8k8I22pVuO6HLNW1Kqpo5wYJ7zFjeplZgp6crVVZg15NI4gQS2PcV4S4zbS1vZ3/FQDWhyB/UXWQqb6XjFj1hPJSRaS0Spg==", "audit.signature.public-key=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmHADDS8d1h3PcSPKwSSlBTQ4BDssTSpwIxkbV+KQhwEDHDlLXoZzDMiaOnUz0/uH4cNFdUtg+LMyNEIWaI/W5/Huq6QNrnnKGdlCXpwlzRRKmbGoZKDh14fjovmtEUzaAZnrFhRlkEojLv0ITyyZAZ9vXhHLvhmL3gdaDFsFFzmY+hZNA7YomUaCPU/0MGHFKqSfywcHmOEv2rVOWb7jFkTxHzsoxxC/15upJHytv7HP4vRak9RxdH5DboC6NQY8+4GJaEclJi27hHcgN6R1S5dg2+k6RI/B3J6WbwcJDvvLOHIV2Oz+B1ZxxKzcp17ykbZNNSK2NW6txSmOy86+IQIDAQAB"})



@ActiveProfiles("dev")



@TestPropertySource(properties = "spring.jpa.hibernate.ddl-auto=create-drop")



class VerificationIntegrationTest {



    @Test

    void testTamperRedaction_ModifyPayloadAfterRedaction() throws Exception {

        AuditEventResponse evt = auditService.createAuditEvent(createRequest("actor-1"));

        

        // 1. Legitimate redaction

        String originalContentHash = repository.findById(evt.getId()).get().getContentHash();

        String legitimateRedactionDigest = hashService.calculateRedactionDigest(originalContentHash, mapper.readTree("{\"redacted\":true}"));

        

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



}



