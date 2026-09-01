package com.example.auditlog.service;

import com.example.auditlog.dto.AuditEventRequest;
import com.example.auditlog.dto.AuditEventResponse;
import com.example.auditlog.entity.AuditRecord;
import com.example.auditlog.repository.AuditRecordRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;

@Service
@RequiredArgsConstructor
public class AuditService {

    private final AuditRecordRepository auditRecordRepository;

    /**
     * Creates and persists a new AuditRecord based on the provided request.
     */
    @Transactional
    public AuditEventResponse createAuditEvent(AuditEventRequest request) {
        // Use the caller's timestamp if provided; otherwise, default to the current time.
        Instant recordTimestamp = request.getTimestamp() != null ? request.getTimestamp() : Instant.now();

        // Build the entity. Note that the previousHash and recordHash are left null intentionally.
        AuditRecord record = AuditRecord.builder()
                .eventType(request.getEventType())
                .actorId(request.getActorId())
                .resourceType(request.getResourceType())
                .resourceId(request.getResourceId())
                .payload(request.getPayload())
                .timestamp(recordTimestamp)
                // status defaults to ACTIVE via the entity's @Builder.Default
                .build();

        // Save to the database and flush to ensure DB-generated fields (like createdAt) are populated
        AuditRecord savedRecord = auditRecordRepository.saveAndFlush(record);

        // Map the saved entity back to the response DTO
        return AuditEventResponse.builder()
                .id(savedRecord.getId())
                .eventType(savedRecord.getEventType())
                .actorId(savedRecord.getActorId())
                .resourceType(savedRecord.getResourceType())
                .resourceId(savedRecord.getResourceId())
                .payload(savedRecord.getPayload())
                .timestamp(savedRecord.getTimestamp())
                .status(savedRecord.getStatus())
                .createdAt(savedRecord.getCreatedAt())
                .build();
    }
}
