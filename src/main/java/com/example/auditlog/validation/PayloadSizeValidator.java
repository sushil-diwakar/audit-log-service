package com.example.auditlog.validation;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

import java.io.IOException;

/**
 * Enforces maximum byte size and maximum nesting depth on a JsonNode payload.
 * Protects the service against JSON bomb attacks and oversized request bodies
 * that could cause excessive memory allocation or processing time.
 */
public class PayloadSizeValidator implements ConstraintValidator<ValidPayload, JsonNode> {

    private int maxBytes;
    private int maxDepth;
    private final ObjectMapper mapper = new ObjectMapper();

    @Override
    public void initialize(ValidPayload annotation) {
        this.maxBytes = annotation.maxBytes();
        this.maxDepth = annotation.maxDepth();
    }

    @Override
    public boolean isValid(JsonNode node, ConstraintValidatorContext context) {
        if (node == null) {
            return true; // null is handled by @NotNull separately
        }

        // Check serialized size
        try {
            byte[] serialized = mapper.writeValueAsBytes(node);
            if (serialized.length > maxBytes) {
                context.disableDefaultConstraintViolation();
                context.buildConstraintViolationWithTemplate(
                        "Payload size " + serialized.length + " bytes exceeds maximum of " + maxBytes + " bytes"
                ).addConstraintViolation();
                return false;
            }
        } catch (IOException e) {
            return false;
        }

        // Check nesting depth
        int depth = computeDepth(node, 0);
        if (depth > maxDepth) {
            context.disableDefaultConstraintViolation();
            context.buildConstraintViolationWithTemplate(
                    "Payload nesting depth " + depth + " exceeds maximum of " + maxDepth
            ).addConstraintViolation();
            return false;
        }

        return true;
    }

    private int computeDepth(JsonNode node, int currentDepth) {
        if (currentDepth > maxDepth) {
            return currentDepth; // short-circuit — already too deep
        }
        if (!node.isContainerNode()) {
            return currentDepth;
        }
        int maxChildDepth = currentDepth;
        for (JsonNode child : node) {
            int childDepth = computeDepth(child, currentDepth + 1);
            if (childDepth > maxChildDepth) {
                maxChildDepth = childDepth;
            }
        }
        return maxChildDepth;
    }
}
