package com.example.auditlog.service;

import com.example.auditlog.dto.AuditEventRequest;
import com.example.auditlog.dto.AuditEventResponse;
import com.example.auditlog.dto.PagedResponse;
import com.example.auditlog.entity.AuditRecord;
import com.example.auditlog.repository.AuditRecordRepository;
import com.example.auditlog.repository.AuditRecordSpecification;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class AuditService {

    private final AuditRecordRepository auditRecordRepository;
    private final HashService hashService;

    public static final String GENESIS_HASH = "GENESIS";
    private static final int MAX_RETRIES = 3;

    /**
     * Creates and persists a new AuditRecord based on the provided request.
     * Incorporates retry logic to handle concurrent chain append collisions.
     */
    public AuditEventResponse createAuditEvent(AuditEventRequest request) {
        for (int i = 0; i < MAX_RETRIES; i++) {
            try {
                return doCreateAuditEvent(request);
            } catch (org.springframework.dao.DataIntegrityViolationException e) {
                // If the unique constraint on previousHash is violated by a concurrent writer,
                // we catch and retry. If max retries are exhausted, bubble up an exception.
                if (i == MAX_RETRIES - 1) {
                    throw new IllegalStateException("Failed to append to audit log due to high concurrency. Please try again.", e);
                }
            }
        }
        throw new IllegalStateException("Unreachable");
    }

    private AuditEventResponse doCreateAuditEvent(AuditEventRequest request) {
        Instant recordTimestamp = request.getTimestamp() != null ? request.getTimestamp() : Instant.now().truncatedTo(java.time.temporal.ChronoUnit.MILLIS);

        // 1. Construct the base record
        AuditRecord record = AuditRecord.builder()
                .eventType(request.getEventType())
                .actorId(request.getActorId())
                .resourceType(request.getResourceType())
                .resourceId(request.getResourceId())
                .payload(request.getPayload())
                .timestamp(recordTimestamp)
                .build();

        // 2. Compute Content Hash
        String contentHash = hashService.calculateContentHash(record);
        record.setContentHash(contentHash);

        // 3. Determine previous hash by finding the absolute latest record (true append order)
        String previousHash = auditRecordRepository.findCurrentChainHead()
                .map(AuditRecord::getRecordHash)
                .orElse(GENESIS_HASH);

        record.setPreviousHash(previousHash);

        // 4. Compute Record Hash
        String recordHash = hashService.calculateRecordHash(contentHash, previousHash);
        record.setRecordHash(recordHash);

        // 5. Save and Flush. Since previousHash is unique, concurrent identical appends will fail here.
        AuditRecord savedRecord = auditRecordRepository.saveAndFlush(record);

        return mapToResponse(savedRecord);
    }

    /**
     * Retrieves audit events using optional filters and pagination.
     */
    @Transactional(readOnly = true)
    public PagedResponse<AuditEventResponse> getAuditEvents(
            String actorId, String resourceType, String resourceId, String eventType,
            Instant from, Instant to, int page, int size) {
        
        boolean hasResourceType = resourceType != null && !resourceType.isBlank();
        boolean hasResourceId = resourceId != null && !resourceId.isBlank();

        if (hasResourceType != hasResourceId) {
            throw new IllegalArgumentException(
                    "resourceType and resourceId must be provided together");
        }

        if (from != null && to != null && from.isAfter(to)) {
            throw new IllegalArgumentException("'from' timestamp cannot be after 'to' timestamp");
        }

        // Deterministic ordering: primary timestamp ASC, secondary id ASC
        Sort sort = Sort.by("timestamp").ascending().and(Sort.by("id").ascending());
        Pageable pageable = PageRequest.of(page, size, sort);

        Specification<AuditRecord> spec = AuditRecordSpecification.withFilters(
                actorId, resourceType, resourceId, eventType, from, to);

        Page<AuditRecord> recordsPage = auditRecordRepository.findAll(spec, pageable);

        List<AuditEventResponse> content = recordsPage.getContent().stream()
                .map(this::mapToResponse)
                .collect(Collectors.toList());

        return PagedResponse.<AuditEventResponse>builder()
                .content(content)
                .pageNumber(recordsPage.getNumber())
                .pageSize(recordsPage.getSize())
                .totalElements(recordsPage.getTotalElements())
                .totalPages(recordsPage.getTotalPages())
                .build();
    }

    private AuditEventResponse mapToResponse(AuditRecord record) {
        return AuditEventResponse.builder()
                .id(record.getId())
                .eventType(record.getEventType())
                .actorId(record.getActorId())
                .resourceType(record.getResourceType())
                .resourceId(record.getResourceId())
                .payload(record.getPayload())
                .timestamp(record.getTimestamp())
                .status(record.getStatus())
                .createdAt(record.getCreatedAt())
                .build();
    }
}
