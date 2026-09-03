package com.example.auditlog.controller;

import com.example.auditlog.dto.VerificationResponse;
import org.springframework.security.access.prepost.PreAuthorize;
import com.example.auditlog.service.ChainVerificationService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/audit/verify")
@RequiredArgsConstructor
public class VerificationController {

    private final ChainVerificationService chainVerificationService;

    @PreAuthorize("hasAuthority(\'SCOPE_audit:verify\')")
    @GetMapping
    public ResponseEntity<VerificationResponse> verifyChain() {
        return ResponseEntity.ok(chainVerificationService.verifyChain());
    }
}
