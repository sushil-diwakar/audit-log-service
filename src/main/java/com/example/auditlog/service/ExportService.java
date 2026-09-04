package com.example.auditlog.service;

import com.example.auditlog.dto.ExportBundle;
import com.example.auditlog.dto.ExportMetadata;
import com.example.auditlog.dto.ExportRecord;
import com.example.auditlog.entity.AuditRecord;
import com.example.auditlog.repository.AuditRecordRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class ExportService {

    private final AuditRecordRepository auditRecordRepository;
    private final ExportSignatureService signatureService;

    @Transactional(readOnly = true)
    public ExportBundle export(String actorId, String resourceId) {
        if ((actorId == null || actorId.isBlank()) && (resourceId == null || resourceId.isBlank())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "At least one of actorId or resourceId must be provided");
        }

        // Fetch all records to guarantee perfect topological order traversal
        List<AuditRecord> allRecords = auditRecordRepository.findAll();
        
        if (allRecords.isEmpty()) {
            return buildEmptyBundle(actorId, resourceId);
        }

        Map<String, AuditRecord> byPreviousHash = allRecords.stream()
                .collect(Collectors.toMap(AuditRecord::getPreviousHash, r -> r));

        List<ExportRecord> matchingRecords = new ArrayList<>();
        AuditRecord current = byPreviousHash.get(AuditService.GENESIS_HASH);

        while (current != null) {
            boolean matchesActor = actorId == null || actorId.equals(current.getActorId());
            boolean matchesResource = resourceId == null || resourceId.equals(current.getResourceId());

            if (matchesActor && matchesResource) {
                matchingRecords.add(mapToExportRecord(current));
            }

            current = byPreviousHash.get(current.getRecordHash());
        }

        String globalTipHash = auditRecordRepository.findCurrentChainHead()
                .map(AuditRecord::getRecordHash)
                .orElse(AuditService.GENESIS_HASH);

        ExportMetadata metadata = ExportMetadata.builder()
                .generatedAt(Instant.now())
                .query(ExportMetadata.QueryFilter.builder()
                        .actorId(actorId)
                        .resourceId(resourceId)
                        .build())
                .recordCount(matchingRecords.size())
                .firstExportedRecordPreviousHash(matchingRecords.isEmpty() ? null : matchingRecords.get(0).getPreviousHash())
                .firstExportedRecordHash(matchingRecords.isEmpty() ? null : matchingRecords.get(0).getRecordHash())
                .lastExportedRecordHash(matchingRecords.isEmpty() ? null : matchingRecords.get(matchingRecords.size() - 1).getRecordHash())
                .globalChainTipHash(globalTipHash)
                .build();

        ExportBundle bundle = ExportBundle.builder()
                .metadata(metadata)
                .records(matchingRecords)
                .build();
                
        signatureService.signBundle(bundle);
        return bundle;
    }

    private ExportBundle buildEmptyBundle(String actorId, String resourceId) {
        ExportBundle bundle = ExportBundle.builder()
                .metadata(ExportMetadata.builder()
                        .generatedAt(Instant.now())
                        .query(ExportMetadata.QueryFilter.builder()
                                .actorId(actorId)
                                .resourceId(resourceId)
                                .build())
                        .recordCount(0)
                        .globalChainTipHash(AuditService.GENESIS_HASH)
                        .build())
                .records(new ArrayList<>())
                .build();
                
        signatureService.signBundle(bundle);
        return bundle;
    }

    private ExportRecord mapToExportRecord(AuditRecord record) {
        return ExportRecord.builder()
                .id(record.getId())
                .eventType(record.getEventType())
                .actorId(record.getActorId())
                .resourceType(record.getResourceType())
                .resourceId(record.getResourceId())
                .payload(record.getPayload())
                .timestamp(record.getTimestamp())
                .status(record.getStatus())
                .contentHash(record.getContentHash())
                .previousHash(record.getPreviousHash())
                .recordHash(record.getRecordHash())
                .redactionDigest(record.getRedactionDigest())
                .build();
    }
}
