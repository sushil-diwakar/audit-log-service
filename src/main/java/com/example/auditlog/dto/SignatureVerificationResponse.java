package com.example.auditlog.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SignatureVerificationResponse {
    private boolean valid;
    private boolean signatureValid;
    private boolean chainValid;
    private String message;
}
