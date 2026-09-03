package com.example.auditlog.controller;

import com.example.auditlog.dto.ExportBundle;
import org.springframework.security.access.prepost.PreAuthorize;
import com.example.auditlog.service.ExportService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/audit")
@RequiredArgsConstructor
public class ExportController {

    private final ExportService exportService;

    @PreAuthorize("hasAuthority(\'SCOPE_audit:export\')")
    @GetMapping("/export")
    public ResponseEntity<ExportBundle> exportAuditRecords(
            @RequestParam(required = false) String actorId,
            @RequestParam(required = false) String resourceId) {
        
        ExportBundle bundle = exportService.export(actorId, resourceId);
        return ResponseEntity.ok(bundle);
    }
}
