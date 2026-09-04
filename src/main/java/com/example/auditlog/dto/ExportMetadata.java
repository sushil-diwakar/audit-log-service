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
    private ExportSignature signature;

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class ExportSignature {
        private String algorithm;
        private String keyId;
        private String signatureValue;
        private String canonicalizationVersion;
        private String publicKeyReference;
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class QueryFilter {
        private String actorId;
        private String resourceId;
    }
}
