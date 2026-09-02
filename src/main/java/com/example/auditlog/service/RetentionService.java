package com.example.auditlog.service;

import com.example.auditlog.dto.ArchivalResponse;
import com.example.auditlog.repository.AuditRecordRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;

@Service
@RequiredArgsConstructor
public class RetentionService {

    private final AuditRecordRepository auditRecordRepository;

    /**
     * Soft archives all ACTIVE audit records that have an event timestamp strictly older than the provided cutoff.
     * An archived record maintains its original cryptographic hashes and contents, remaining part of the unbroken hash chain.
     *
     * @param cutoff The timestamp before which records will be archived
     * @return ArchivalResponse detailing how many records were successfully archived.
     */
    @Transactional
    public ArchivalResponse archiveRecordsBefore(Instant cutoff) {
        if (cutoff == null) {
            throw new IllegalArgumentException("Cutoff timestamp cannot be null");
        }
        
        int archivedCount = auditRecordRepository.archiveOldRecords(cutoff);
        
        return ArchivalResponse.builder()
                .archivedCount(archivedCount)
                .cutoffTimestamp(cutoff)
                .build();
    }
}
