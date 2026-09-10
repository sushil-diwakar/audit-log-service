package com.example.auditlog.controller;

import com.example.auditlog.dto.ExportBundle;
import org.springframework.security.access.prepost.PreAuthorize;
import com.example.auditlog.service.ExportService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import com.example.auditlog.dto.SignatureVerificationResponse;
import com.example.auditlog.service.ExportSignatureService;
import com.example.auditlog.service.ChainVerificationService;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/audit")
@RequiredArgsConstructor
public class ExportController {

    private final ExportService exportService;
    private final ExportSignatureService exportSignatureService;
    private final ChainVerificationService chainVerificationService;

    @PreAuthorize("hasAuthority(\'SCOPE_audit:export\')")
    @GetMapping("/export")
    public ResponseEntity<ExportBundle> exportAuditRecords(
            @RequestParam(required = false) String actorId,
            @RequestParam(required = false) String resourceId) {
        
        ExportBundle bundle = exportService.export(actorId, resourceId);
        return ResponseEntity.ok(bundle);
    }

    @PostMapping("/export/verify")
    public ResponseEntity<SignatureVerificationResponse> verifyExportBundle(@RequestBody ExportBundle bundle) {
        boolean sigValid = exportSignatureService.verifySignature(bundle);
        boolean chainValid = chainVerificationService.verifyExportChain(bundle);

        boolean valid = sigValid && chainValid;
        String message = buildVerificationMessage(sigValid, chainValid);

        SignatureVerificationResponse response = SignatureVerificationResponse.builder()
                .valid(valid)
                .signatureValid(sigValid)
                .chainValid(chainValid)
                .message(message)
                .build();

        return ResponseEntity.ok(response);
    }

    private String buildVerificationMessage(boolean sigValid, boolean chainValid) {
        if (sigValid && chainValid) {
            return "Export bundle signature and chain integrity verified successfully";
        } else if (!sigValid && !chainValid) {
            return "Export bundle verification failed: invalid signature and broken chain integrity";
        } else if (!sigValid) {
            return "Export bundle verification failed: invalid digital signature";
        } else {
            return "Export bundle verification failed: chain integrity violation detected";
        }
    }

}
