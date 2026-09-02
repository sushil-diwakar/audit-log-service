package com.example.auditlog.controller;

import com.example.auditlog.dto.RedactionRequest;
import com.example.auditlog.dto.RedactionResponse;
import com.example.auditlog.service.RedactionService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.UUID;

@RestController
@RequestMapping("/audit/events")
@RequiredArgsConstructor
public class RedactionController {

    private final RedactionService redactionService;

    @PostMapping("/{id}/redact")
    public ResponseEntity<RedactionResponse> redactEvent(
            @PathVariable UUID id,
            @Valid @RequestBody RedactionRequest request) {
        
        RedactionResponse response = redactionService.redactRecord(id, request);
        return ResponseEntity.ok(response);
    }
}
