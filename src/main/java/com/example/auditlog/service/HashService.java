package com.example.auditlog.service;

import com.example.auditlog.entity.AuditRecord;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Map;
import java.util.TreeMap;

@Service
@RequiredArgsConstructor
public class HashService {

    private final ObjectMapper mapper;

    /**
     * Calculates a deterministic SHA-256 hash for the given AuditRecord.
     * Excludes database-generated and mutability fields like id, status, createdAt, previousHash, and recordHash.
     */
    public String calculateContentHash(AuditRecord record) {
        try {
            // Use TreeMap to ensure properties are canonically ordered alphabetically by key
            TreeMap<String, Object> canonicalMap = new TreeMap<>();
            
            canonicalMap.put("actorId", record.getActorId());
            canonicalMap.put("eventType", record.getEventType());
            canonicalMap.put("resourceId", record.getResourceId());
            canonicalMap.put("resourceType", record.getResourceType());
            
            // Format timestamp as a consistent ISO-8601 string, or explicit null
            canonicalMap.put("timestamp", record.getTimestamp() != null ? record.getTimestamp().toString() : null);
            
            // Deeply canonicalize the payload to ensure deterministic key ordering
            canonicalMap.put("payload", canonicalizeNode(record.getPayload()));

            // Serialize the strictly ordered map to a JSON string
            String canonicalString = mapper.writeValueAsString(canonicalMap);

            // Hash the canonical string
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(canonicalString.getBytes(StandardCharsets.UTF_8));

            return bytesToHex(hashBytes);

        } catch (NoSuchAlgorithmException | JsonProcessingException e) {
            throw new IllegalStateException("Failed to calculate content hash", e);
        }
    }

    /**
     * Calculates the final record hash by chaining the content hash with the previous record's hash.
     */
    public String calculateRecordHash(String contentHash, String previousHash) {
        try {
            String combined = contentHash + "|" + previousHash;
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(combined.getBytes(StandardCharsets.UTF_8));
            return bytesToHex(hashBytes);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Failed to calculate record hash", e);
        }
    }

    /**
     * Recursively sorts the fields of a JSON object to ensure deterministic representation.
     */
    private JsonNode canonicalizeNode(JsonNode node) {
        if (node == null || node.isNull()) {
            return mapper.nullNode();
        }

        if (node.isObject()) {
            ObjectNode sortedNode = mapper.createObjectNode();
            TreeMap<String, JsonNode> sortedFields = new TreeMap<>();
            
            node.fields().forEachRemaining(entry -> 
                sortedFields.put(entry.getKey(), canonicalizeNode(entry.getValue()))
            );
            
            sortedFields.forEach(sortedNode::set);
            return sortedNode;
        } else if (node.isArray()) {
            ArrayNode arrayNode = mapper.createArrayNode();
            node.elements().forEachRemaining(element -> arrayNode.add(canonicalizeNode(element)));
            return arrayNode;
        }
        
        // Return primitives as-is
        return node;
    }

    /**
     * Converts a byte array into a lowercase hexadecimal string.
     */

    /**
     * Calculates a cryptographic commitment for a redaction event.
     * Binds the original content hash to the new redacted payload.
     */
    public String calculateRedactionDigest(String originalContentHash, JsonNode redactedPayload) {
        try {
            String payloadString = mapper.writeValueAsString(canonicalizeNode(redactedPayload));
            String combined = originalContentHash + "|REDACTED|" + payloadString;
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(combined.getBytes(StandardCharsets.UTF_8));
            return bytesToHex(hashBytes);
        } catch (NoSuchAlgorithmException | JsonProcessingException e) {
            throw new IllegalStateException("Failed to calculate redaction digest", e);
        }
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder(2 * bytes.length);
        for (byte b : bytes) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }
}
