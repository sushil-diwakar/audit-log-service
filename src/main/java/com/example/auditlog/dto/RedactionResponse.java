package com.example.auditlog.dto;

import com.example.auditlog.entity.AuditRecordStatus;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;
import java.util.UUID;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RedactionResponse {
    private UUID recordId;
    private AuditRecordStatus status;
    private List<String> redactedPaths;
}
