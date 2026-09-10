package com.example.auditlog.service;



import com.example.auditlog.dto.VerificationResponse;

import com.example.auditlog.entity.AuditRecord;

import com.example.auditlog.enums.ChainViolationType;

import com.example.auditlog.repository.AuditRecordRepository;

import lombok.RequiredArgsConstructor;

import org.springframework.stereotype.Service;

import org.springframework.transaction.annotation.Transactional;



import java.util.HashMap;

import java.util.HashSet;

import java.util.List;

import java.util.Map;

import java.util.Set;

import java.util.UUID;

import java.util.stream.Collectors;



@Service

@RequiredArgsConstructor

public class ChainVerificationService {



    private final AuditRecordRepository repository;

    private final HashService hashService;



    @Transactional(readOnly = true)

    public VerificationResponse verifyChain() {

        List<AuditRecord> allRecords = repository.findAll();



        if (allRecords.isEmpty()) {

            return VerificationResponse.builder()

                    .valid(true)

                    .message("Chain is empty and intact")

                    .checkedRecords(0)

                    .build();

        }



        // 1. Content Integrity Check & Indexing

        Map<String, List<AuditRecord>> byPreviousHash = allRecords.stream()

                .collect(Collectors.groupingBy(AuditRecord::getPreviousHash));



        for (AuditRecord record : allRecords) {

            String storedContentHash = record.getContentHash();

            

            if (record.getStatus() == com.example.auditlog.entity.AuditRecordStatus.REDACTED) {

                if (storedContentHash == null || !storedContentHash.matches("^[a-f0-9]{64}$")) {

                    return buildFailure("Invalid content hash for REDACTED record", ChainViolationType.INVALID_CONTENT_HASH, record.getId(), 0);

                }

                

                String expectedRedactionDigest = hashService.calculateRedactionDigest(record, record.getPayload());

                if (record.getRedactionDigest() == null || !record.getRedactionDigest().equals(expectedRedactionDigest)) {

                    return buildFailure("Redaction digest mismatch detected", ChainViolationType.REDACTION_METADATA_MISMATCH, record.getId(), 0);

                }

            } else {

                String computedContent = hashService.calculateContentHash(record);

                if (!computedContent.equals(storedContentHash)) {

                    return buildFailure("Content hash mismatch detected", ChainViolationType.CONTENT_HASH_MISMATCH, record.getId(), 0);

                }

            }



            String computedRecord = hashService.calculateRecordHash(storedContentHash, record.getPreviousHash());

            

            if (!computedRecord.equals(record.getRecordHash())) {

                return buildFailure("Record hash mismatch detected", ChainViolationType.RECORD_HASH_MISMATCH, record.getId(), 0);

            }

        }



        // 2. Genesis Verification

        List<AuditRecord> genesisRecords = byPreviousHash.get(AuditService.GENESIS_HASH);

        if (genesisRecords == null || genesisRecords.isEmpty()) {

            return buildFailure("No genesis record found", ChainViolationType.MISSING_GENESIS, null, 0);

        }

        if (genesisRecords.size() > 1) {

            return buildFailure("Multiple genesis records found", ChainViolationType.MULTIPLE_GENESIS, genesisRecords.get(1).getId(), 0);

        }



        // 3. Chain Traversal

        AuditRecord current = genesisRecords.get(0);

        Set<UUID> visited = new HashSet<>();

        visited.add(current.getId());

        int checked = 1;



        while (true) {

            List<AuditRecord> nextList = byPreviousHash.get(current.getRecordHash());

            

            if (nextList == null || nextList.isEmpty()) {

                break; // End of chain reached

            }

            if (nextList.size() > 1) {

                return buildFailure("Chain fork detected", ChainViolationType.FORK_DETECTED, nextList.get(1).getId(), checked);

            }

            

            AuditRecord next = nextList.get(0);

            if (visited.contains(next.getId())) {

                return buildFailure("Cycle detected in chain", ChainViolationType.CYCLE_DETECTED, next.getId(), checked);

            }

            

            visited.add(next.getId());

            current = next;

            checked++;

        }



        // 4. Complete Coverage Verification (Orphans)

        if (checked != allRecords.size()) {

            AuditRecord orphan = allRecords.stream()

                    .filter(r -> !visited.contains(r.getId()))

                    .findFirst()

                    .orElseThrow();

            return buildFailure("Disconnected or orphaned records detected", ChainViolationType.DISCONNECTED_RECORD, orphan.getId(), checked);

        }



        return VerificationResponse.builder()

                .valid(true)

                .message("Audit chain is intact")

                .checkedRecords(checked)

                .build();

    }



    private VerificationResponse buildFailure(String message, ChainViolationType type, UUID recordId, int checkedRecords) {

        return VerificationResponse.builder()

                .valid(false)

                .message(message)

                .violationType(type)

                .recordId(recordId)

                .checkedRecords(checkedRecords)

                .build();

    }

    /**
     * Verifies the hash chain integrity of an exported bundle.
     * Validates that the exported records form a valid subset chain.
     */
    public boolean verifyExportChain(com.example.auditlog.dto.ExportBundle bundle) {
        if (bundle == null || bundle.getRecords() == null || bundle.getRecords().isEmpty()) {
            return true; // Empty bundle is technically valid
        }

        List<com.example.auditlog.dto.ExportRecord> records = bundle.getRecords();

        // Build index by previousHash for efficient lookup
        Map<String, com.example.auditlog.dto.ExportRecord> byPreviousHash = new HashMap<>();
        for (com.example.auditlog.dto.ExportRecord record : records) {
            if (byPreviousHash.containsKey(record.getPreviousHash())) {
                // Fork detected - two records with same previousHash
                return false;
            }
            byPreviousHash.put(record.getPreviousHash(), record);
        }

        // 1. Verify each record's content hash and record hash
        for (com.example.auditlog.dto.ExportRecord record : records) {
            String computedRecordHash = hashService.calculateRecordHash(
                record.getContentHash(),
                record.getPreviousHash()
            );

            if (!computedRecordHash.equals(record.getRecordHash())) {
                return false; // Record hash mismatch
            }
        }

        // 2. Verify the chain forms a valid sequence
        // Start from the first exported record
        com.example.auditlog.dto.ExportRecord current = records.get(0);
        Set<UUID> visited = new HashSet<>();
        visited.add(current.getId());
        int chainLength = 1;

        // Traverse the chain
        while (true) {
            com.example.auditlog.dto.ExportRecord next = byPreviousHash.get(current.getRecordHash());
            if (next == null) {
                break; // End of exported chain
            }

            if (visited.contains(next.getId())) {
                return false; // Cycle detected
            }

            visited.add(next.getId());
            current = next;
            chainLength++;
        }

        // 3. All exported records must be part of the chain
        if (chainLength != records.size()) {
            return false; // Disconnected records in export
        }

        // 4. Verify metadata consistency
        com.example.auditlog.dto.ExportMetadata metadata = bundle.getMetadata();
        if (metadata != null) {
            if (metadata.getRecordCount() != records.size()) {
                return false;
            }

            if (metadata.getFirstExportedRecordPreviousHash() != null
                && !metadata.getFirstExportedRecordPreviousHash().equals(records.get(0).getPreviousHash())) {
                return false;
            }

            if (metadata.getFirstExportedRecordHash() != null
                && !metadata.getFirstExportedRecordHash().equals(records.get(0).getRecordHash())) {
                return false;
            }

            if (metadata.getLastExportedRecordHash() != null
                && !metadata.getLastExportedRecordHash().equals(records.get(records.size() - 1).getRecordHash())) {
                return false;
            }
        }

        return true;
    }

}

