package com.example.auditlog.service;

import com.example.auditlog.dto.RedactionRequest;
import com.example.auditlog.dto.RedactionResponse;
import com.example.auditlog.entity.AuditRecord;
import com.example.auditlog.entity.AuditRecordStatus;
import com.example.auditlog.repository.AuditRecordRepository;
import com.fasterxml.jackson.core.JsonPointer;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class RedactionService {

    private final AuditRecordRepository auditRecordRepository;
    private final ObjectMapper objectMapper;

    @Transactional
    public RedactionResponse redactRecord(UUID id, RedactionRequest request) {
        AuditRecord record = auditRecordRepository.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Audit record not found"));

        if (record.getStatus() == AuditRecordStatus.REDACTED) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Record is already redacted");
        }

        JsonNode payloadCopy = record.getPayload().deepCopy();
        List<JsonPointer> validPointers = new java.util.ArrayList<>();

        // 1. Validate all paths strictly before applying any mutations
        for (String pathStr : request.getPaths()) {
            JsonPointer pointer;
            try {
                pointer = JsonPointer.compile(pathStr);
            } catch (IllegalArgumentException e) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid JSON Pointer: " + pathStr);
            }

            if (payloadCopy.at(pointer).isMissingNode()) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Path not found: " + pathStr);
            }
            
            validPointers.add(pointer);
        }

        // 2. Perform all-or-nothing mutations
        ObjectNode redactedMarker = objectMapper.createObjectNode();
        redactedMarker.put("redacted", true);

        for (JsonPointer pointer : validPointers) {
            JsonPointer parentPointer = pointer.head();
            String leafName = pointer.last().getMatchingProperty();
            
            if (parentPointer == null || leafName == null) {
                // If it's the root being redacted (unlikely, but supported)
                payloadCopy = redactedMarker;
            } else {
                JsonNode parentNode = payloadCopy.at(parentPointer);
                if (parentNode.isObject()) {
                    ((ObjectNode) parentNode).set(leafName, redactedMarker);
                } else if (parentNode.isArray()) {
                    int index = pointer.last().getMatchingIndex();
                    if (index >= 0) {
                        ((com.fasterxml.jackson.databind.node.ArrayNode) parentNode).set(index, redactedMarker);
                    }
                }
            }
        }

        // Apply changes
        record.setPayload(payloadCopy);
        record.setStatus(AuditRecordStatus.REDACTED);
        
        auditRecordRepository.save(record);

        return RedactionResponse.builder()
                .recordId(record.getId())
                .status(record.getStatus())
                .redactedPaths(request.getPaths())
                .build();
    }
}
