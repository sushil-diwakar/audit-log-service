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

                

                String expectedRedactionDigest = hashService.calculateRedactionDigest(storedContentHash, record.getPayload());

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

}

