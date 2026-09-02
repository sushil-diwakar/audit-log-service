package com.example.auditlog.dto;

import com.example.auditlog.enums.ChainViolationType;
import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Builder;
import lombok.Data;

import java.util.UUID;

@Data
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class VerificationResponse {
    private boolean valid;
    private String message;
    private int checkedRecords;
    
    // Only populated if valid == false
    private ChainViolationType violationType;
    private UUID recordId;
}
