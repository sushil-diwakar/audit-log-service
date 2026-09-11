package com.example.auditlog.validation;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;

import java.lang.annotation.*;

/**
 * Validates that a JsonNode payload does not exceed size or depth limits,
 * guarding against JSON bombs and oversized request bodies.
 */
@Documented
@Constraint(validatedBy = PayloadSizeValidator.class)
@Target({ElementType.FIELD, ElementType.PARAMETER})
@Retention(RetentionPolicy.RUNTIME)
public @interface ValidPayload {

    String message() default "Payload exceeds allowed size or nesting depth";

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};

    /** Maximum serialized JSON byte size. Default: 65536 (64 KB). */
    int maxBytes() default 65_536;

    /** Maximum nesting depth. Default: 10. */
    int maxDepth() default 10;
}
