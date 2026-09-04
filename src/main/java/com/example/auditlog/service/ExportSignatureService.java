package com.example.auditlog.service;

import com.example.auditlog.dto.ExportBundle;
import com.example.auditlog.dto.ExportMetadata;
import com.example.auditlog.dto.ExportRecord;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Iterator;
import java.util.Map;
import java.util.TreeMap;

@Service
@RequiredArgsConstructor
@Slf4j
public class ExportSignatureService {

    private final ObjectMapper mapper;

    @Value("${audit.signature.key-id:default-key-1}")
    private String keyId;

    @Value("${audit.signature.private-key:}")
    private String privateKeyStr;

    @Value("${audit.signature.public-key:}")
    private String publicKeyStr;

    private static final String ALGORITHM = "SHA256withRSA";
    private static final String CANONICAL_VERSION = "v1";

    public void signBundle(ExportBundle bundle) {
        if (privateKeyStr == null || privateKeyStr.isBlank()) {
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Signing requested but private key is unavailable");
        }

        try {
            PrivateKey privateKey = loadPrivateKey(privateKeyStr);
            String canonical = canonicalizeBundle(bundle);

            Signature signature = Signature.getInstance(ALGORITHM);
            signature.initSign(privateKey);
            signature.update(canonical.getBytes(StandardCharsets.UTF_8));
            byte[] signedBytes = signature.sign();

            ExportMetadata.ExportSignature sig = ExportMetadata.ExportSignature.builder()
                    .algorithm(ALGORITHM)
                    .keyId(keyId)
                    .signatureValue(Base64.getEncoder().encodeToString(signedBytes))
                    .canonicalizationVersion(CANONICAL_VERSION)
                    .publicKeyReference("Public key available via documentation or admin configuration")
                    .build();

            bundle.getMetadata().setSignature(sig);

        } catch (Exception e) {
            log.error("Failed to sign export bundle", e);
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Failed to generate digital signature for export bundle");
        }
    }

    public boolean verifySignature(ExportBundle bundle) {
        if (bundle.getMetadata() == null || bundle.getMetadata().getSignature() == null) {
            return false;
        }

        ExportMetadata.ExportSignature sig = bundle.getMetadata().getSignature();
        if (!CANONICAL_VERSION.equals(sig.getCanonicalizationVersion())) {
            log.warn("Unsupported canonicalization version: {}", sig.getCanonicalizationVersion());
            return false;
        }

        if (publicKeyStr == null || publicKeyStr.isBlank()) {
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Public key not configured for verification");
        }

        try {
            PublicKey publicKey = loadPublicKey(publicKeyStr);
            String canonical = canonicalizeBundle(bundle);

            Signature signature = Signature.getInstance(sig.getAlgorithm());
            signature.initVerify(publicKey);
            signature.update(canonical.getBytes(StandardCharsets.UTF_8));
            
            byte[] signatureBytes = Base64.getDecoder().decode(sig.getSignatureValue());
            return signature.verify(signatureBytes);
        } catch (Exception e) {
            log.error("Failed to verify signature", e);
            return false;
        }
    }

    private String canonicalizeBundle(ExportBundle bundle) throws JsonProcessingException {
        // Deterministic JSON string representation excluding the signature
        
        StringBuilder sb = new StringBuilder();
        sb.append(CANONICAL_VERSION).append("|");
        
        ExportMetadata meta = bundle.getMetadata();
        if (meta != null) {
            sb.append("meta.query.actorId=").append(meta.getQuery() != null ? meta.getQuery().getActorId() : "null").append("|");
            sb.append("meta.query.resourceId=").append(meta.getQuery() != null ? meta.getQuery().getResourceId() : "null").append("|");
            sb.append("meta.recordCount=").append(meta.getRecordCount()).append("|");
            sb.append("meta.firstExportedRecordPreviousHash=").append(meta.getFirstExportedRecordPreviousHash()).append("|");
            sb.append("meta.firstExportedRecordHash=").append(meta.getFirstExportedRecordHash()).append("|");
            sb.append("meta.lastExportedRecordHash=").append(meta.getLastExportedRecordHash()).append("|");
            sb.append("meta.globalChainTipHash=").append(meta.getGlobalChainTipHash()).append("|");
        }

        if (bundle.getRecords() != null) {
            for (ExportRecord r : bundle.getRecords()) {
                sb.append("rec.id=").append(r.getId()).append("|");
                sb.append("rec.eventType=").append(r.getEventType()).append("|");
                sb.append("rec.actorId=").append(r.getActorId()).append("|");
                sb.append("rec.resourceType=").append(r.getResourceType()).append("|");
                sb.append("rec.resourceId=").append(r.getResourceId()).append("|");
                
                String payloadStr = r.getPayload() != null ? canonicalizeNode(r.getPayload()) : "null";
                sb.append("rec.payload=").append(payloadStr).append("|");
                
                sb.append("rec.timestamp=").append(r.getTimestamp() != null ? r.getTimestamp().toString() : "null").append("|");
                sb.append("rec.status=").append(r.getStatus()).append("|");
                sb.append("rec.contentHash=").append(r.getContentHash()).append("|");
                sb.append("rec.previousHash=").append(r.getPreviousHash()).append("|");
                sb.append("rec.recordHash=").append(r.getRecordHash()).append("|");
                sb.append("rec.redactionDigest=").append(r.getRedactionDigest()).append("|");
            }
        }
        
        return sb.toString();
    }

    private String canonicalizeNode(JsonNode node) throws JsonProcessingException {
        if (node.isObject()) {
            Map<String, JsonNode> sortedMap = new TreeMap<>();
            Iterator<Map.Entry<String, JsonNode>> it = node.fields();
            while (it.hasNext()) {
                Map.Entry<String, JsonNode> entry = it.next();
                sortedMap.put(entry.getKey(), entry.getValue());
            }
            StringBuilder sb = new StringBuilder("{");
            boolean first = true;
            for (Map.Entry<String, JsonNode> entry : sortedMap.entrySet()) {
                if (!first) sb.append(",");
                sb.append("\"").append(entry.getKey()).append("\":").append(canonicalizeNode(entry.getValue()));
                first = false;
            }
            sb.append("}");
            return sb.toString();
        } else if (node.isArray()) {
            StringBuilder sb = new StringBuilder("[");
            for (int i = 0; i < node.size(); i++) {
                if (i > 0) sb.append(",");
                sb.append(canonicalizeNode(node.get(i)));
            }
            sb.append("]");
            return sb.toString();
        } else if (node.isNull()) {
            return "null";
        } else if (node.isTextual()) {
            return mapper.writeValueAsString(node.asText());
        } else {
            return node.asText();
        }
    }

    private PrivateKey loadPrivateKey(String key64) throws Exception {
        byte[] clear = Base64.getDecoder().decode(key64.replaceAll("\\s", ""));
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(clear);
        KeyFactory fact = KeyFactory.getInstance("RSA");
        return fact.generatePrivate(keySpec);
    }

    private PublicKey loadPublicKey(String key64) throws Exception {
        byte[] clear = Base64.getDecoder().decode(key64.replaceAll("\\s", ""));
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(clear);
        KeyFactory fact = KeyFactory.getInstance("RSA");
        return fact.generatePublic(keySpec);
    }
}