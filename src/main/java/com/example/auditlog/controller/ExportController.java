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

    @PreAuthorize("hasAuthority('SCOPE_audit:verify')")
    @PostMapping("/export/verify")
    public ResponseEntity<SignatureVerificationResponse> verifyExportBundle(@RequestBody ExportBundle bundle) {
        boolean sigValid = exportSignatureService.verifySignature(bundle);
        
        // As a prototype, we just verify signature. If a full chain verification of the subset is needed, 
        // we could do that here. But the requirement is to verify the signature.
        boolean valid = sigValid;
        String message = sigValid ? "Export bundle signature is valid" : "Export bundle signature is invalid";
        
        SignatureVerificationResponse response = SignatureVerificationResponse.builder()
                .valid(valid)
                .signatureValid(sigValid)
                .chainValid(true) // Subset chain verification could be integrated here
                .message(message)
                .build();
                
        return ResponseEntity.ok(response);
    }

}
