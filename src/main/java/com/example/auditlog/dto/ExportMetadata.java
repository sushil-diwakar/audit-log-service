package com.example.auditlog.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ExportMetadata {
    private Instant generatedAt;
    private QueryFilter query;
    private int recordCount;
    private String firstExportedRecordPreviousHash;
    private String firstExportedRecordHash;
    private String lastExportedRecordHash;
    private String globalChainTipHash;

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class QueryFilter {
        private String actorId;
        private String resourceId;
    }
}
