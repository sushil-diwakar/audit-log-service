package com.example.auditlog.controller;

import com.example.auditlog.dto.AuditEventRequest;
import com.example.auditlog.dto.AuditEventResponse;
import com.example.auditlog.dto.PagedResponse;
import com.example.auditlog.service.AuditService;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import jakarta.validation.ConstraintViolationException;
import java.time.Instant;
import java.util.Map;

@RestController
@RequestMapping("/audit/events")
@RequiredArgsConstructor
@Validated // Required for method-level constraint validation on @RequestParam
public class AuditController {

    private final AuditService auditService;

    /**
     * Endpoint to create a new audit event.
     * Requires valid DTO fields and returns HTTP 201 Created on success.
     */
    @PostMapping
    public ResponseEntity<AuditEventResponse> createEvent(@Valid @RequestBody AuditEventRequest request) {
        AuditEventResponse response = auditService.createAuditEvent(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    /**
     * Endpoint to query and filter audit events.
     */
    @GetMapping
    public ResponseEntity<PagedResponse<AuditEventResponse>> getEvents(
            @RequestParam(required = false) String actorId,
            @RequestParam(required = false) String resourceType,
            @RequestParam(required = false) String resourceId,
            @RequestParam(required = false) String eventType,
            @RequestParam(required = false) Instant from,
            @RequestParam(required = false) Instant to,
            @RequestParam(defaultValue = "0") @Min(0) int page,
            @RequestParam(defaultValue = "20") @Min(1) @Max(100) int size) {
        
        PagedResponse<AuditEventResponse> response = auditService.getAuditEvents(
                actorId, resourceType, resourceId, eventType, from, to, page, size);
        return ResponseEntity.ok(response);
    }



    /**
     * Exception handler for constraint violations on parameters or illegal arguments
     */
    @ExceptionHandler({ConstraintViolationException.class, IllegalArgumentException.class})
    public ResponseEntity<Object> handleValidationExceptions(Exception e) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of("error", e.getMessage()));
    }
}
