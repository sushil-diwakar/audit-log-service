package com.example.auditlog.controller;

import com.example.auditlog.dto.AuditEventRequest;
import com.example.auditlog.dto.AuditEventResponse;
import com.example.auditlog.service.AuditService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/audit/events")
@RequiredArgsConstructor
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
}
