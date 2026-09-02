package com.example.auditlog.controller;

import com.example.auditlog.dto.ArchivalResponse;
import com.example.auditlog.service.RetentionService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;

@RestController
@RequestMapping("/audit/retention")
@RequiredArgsConstructor
public class RetentionController {

    private final RetentionService retentionService;

    /**
     * Endpoint to soft-archive audit records older than a specific event timestamp.
     * 
     * @param before The cutoff ISO-8601 timestamp. E.g., 2024-01-01T00:00:00Z
     */
    @PostMapping("/archive")
    public ResponseEntity<ArchivalResponse> archive(@RequestParam("before") Instant before) {
        ArchivalResponse response = retentionService.archiveRecordsBefore(before);
        return ResponseEntity.ok(response);
    }
}
