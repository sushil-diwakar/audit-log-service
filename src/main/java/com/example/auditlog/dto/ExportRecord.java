package com.example.auditlog.dto;

import com.example.auditlog.entity.AuditRecordStatus;
import com.fasterxml.jackson.databind.JsonNode;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.UUID;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ExportRecord {
    private UUID id;
    private String eventType;
    private String actorId;
    private String resourceType;
    private String resourceId;
    private JsonNode payload;
    private Instant timestamp;
    private AuditRecordStatus status;
    private String contentHash;
    private String previousHash;
    private String recordHash;
}
