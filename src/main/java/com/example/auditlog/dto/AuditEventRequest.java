package com.example.auditlog.dto;

import com.fasterxml.jackson.databind.JsonNode;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.Data;
import java.time.Instant;

@Data
public class AuditEventRequest {

    @NotBlank(message = "eventType is required")
    @Size(max = 100, message = "eventType must not exceed 100 characters")
    private String eventType;

    @NotBlank(message = "actorId is required")
    @Size(max = 100, message = "actorId must not exceed 100 characters")
    private String actorId;

    @NotBlank(message = "resourceType is required")
    @Size(max = 100, message = "resourceType must not exceed 100 characters")
    private String resourceType;

    @NotBlank(message = "resourceId is required")
    @Size(max = 100, message = "resourceId must not exceed 100 characters")
    private String resourceId;

    @NotNull(message = "payload is required")
    private JsonNode payload;

    private Instant timestamp;
}
