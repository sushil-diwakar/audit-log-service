package com.example.auditlog.dto;

import lombok.Builder;
import lombok.Data;
import java.time.Instant;

@Data
@Builder
public class ArchivalResponse {
    private int archivedCount;
    private Instant cutoffTimestamp;
}
