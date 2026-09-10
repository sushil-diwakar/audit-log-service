package com.example.auditlog.service;

import com.example.auditlog.entity.AuditRecord;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.util.UUID;

/**
 * Service responsible for enforcing resource-level authorization.
 * Prevents BOLA (Broken Object Level Authorization) and IDOR (Insecure Direct Object Reference) attacks
 * by validating that authenticated users can only access resources they own.
 */
@Service
@RequiredArgsConstructor
public class ResourceAuthorizationService {

    /**
     * Extracts the current authenticated principal (user ID/tenant ID) from the security context.
     * In dev profile, this is the username. In prod profile, this should be extracted from JWT claims.
     */
    public String getCurrentPrincipal() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()) {
            throw new AccessDeniedException("No authenticated user found");
        }

        // In production, extract from JWT claims (e.g., "sub" or custom "tenantId" claim)
        // For dev profile, use the username
        return authentication.getName();
    }

    /**
     * Validates that the current principal owns the specified actor.
     * In a multi-tenant system, this ensures users can only query their own events.
     *
     * @param actorId The actor being queried
     * @throws AccessDeniedException if the current principal doesn't own this actor
     */
    public void validateActorAccess(String actorId) {
        if (actorId == null || actorId.isBlank()) {
            return; // No actor filter specified, allow (will be filtered by other means)
        }

        String principal = getCurrentPrincipal();

        // For now, enforce that actorId must match principal or start with principal prefix
        // In production, this would check against a tenant/ownership database
        if (!actorId.equals(principal) && !actorId.startsWith(principal + ":")) {
            throw new AccessDeniedException(
                String.format("Access denied: Cannot query events for actor '%s'", actorId));
        }
    }

    /**
     * Validates that the current principal owns the specified resource.
     *
     * @param resourceType The resource type being queried
     * @param resourceId The resource ID being queried
     * @throws AccessDeniedException if the current principal doesn't own this resource
     */
    public void validateResourceAccess(String resourceType, String resourceId) {
        if (resourceType == null || resourceType.isBlank() || resourceId == null || resourceId.isBlank()) {
            return; // No resource filter specified
        }

        String principal = getCurrentPrincipal();

        // In production, check resource ownership in database
        // For prototype: enforce that resourceId contains principal or is public
        if (!resourceId.contains(principal) && !resourceId.startsWith("public:")) {
            throw new AccessDeniedException(
                String.format("Access denied: Cannot access resource '%s:%s'", resourceType, resourceId));
        }
    }

    /**
     * Validates that the current principal owns the audit record being accessed.
     * Used for redaction and individual record access operations.
     *
     * @param record The audit record being accessed
     * @throws AccessDeniedException if the current principal doesn't own this record
     */
    public void validateRecordAccess(AuditRecord record) {
        if (record == null) {
            throw new IllegalArgumentException("Record cannot be null");
        }

        String principal = getCurrentPrincipal();
        String actorId = record.getActorId();

        // Enforce ownership: actorId must match or be associated with current principal
        if (!actorId.equals(principal) && !actorId.startsWith(principal + ":")) {
            throw new AccessDeniedException(
                String.format("Access denied: Cannot access record %s (owned by %s)",
                    record.getId(), actorId));
        }
    }

    /**
     * Validates that the provided actorId matches the current principal.
     * Used when creating new audit events to prevent users from creating events for other actors.
     *
     * @param actorId The actor ID in the creation request
     * @throws AccessDeniedException if actorId doesn't match current principal
     */
    public void validateActorOwnership(String actorId) {
        String principal = getCurrentPrincipal();

        // When creating events, actorId must exactly match or be a sub-entity of the principal
        if (!actorId.equals(principal) && !actorId.startsWith(principal + ":")) {
            throw new AccessDeniedException(
                String.format("Access denied: Cannot create events for actor '%s'. " +
                    "You can only create events for your own account.", actorId));
        }
    }

    /**
     * Checks if the current principal has admin privileges.
     * Admin users can bypass ownership checks for verification and export operations.
     */
    public boolean isAdmin() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null) {
            return false;
        }

        // Check for admin role/scope
        return authentication.getAuthorities().stream()
            .anyMatch(auth -> auth.getAuthority().equals("SCOPE_audit:admin")
                           || auth.getAuthority().equals("ROLE_ADMIN"));
    }

    /**
     * Validates export access. Admins can export any data; regular users can only export their own.
     */
    public void validateExportAccess(String actorId, String resourceId) {
        if (isAdmin()) {
            return; // Admins can export anything
        }

        // Regular users can only export their own data
        if (actorId != null && !actorId.isBlank()) {
            validateActorAccess(actorId);
        }

        if (resourceId != null && !resourceId.isBlank()) {
            String principal = getCurrentPrincipal();
            if (!resourceId.contains(principal) && !resourceId.startsWith("public:")) {
                throw new AccessDeniedException(
                    String.format("Access denied: Cannot export resource '%s'", resourceId));
            }
        }
    }
}
