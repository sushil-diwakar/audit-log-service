package com.example.auditlog.entity;

import com.fasterxml.jackson.databind.JsonNode;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "audit_records")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AuditRecord {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(nullable = false, length = 100)
    private String eventType;

    @Column(nullable = false, length = 100)
    private String actorId;

    @Column(nullable = false, length = 100)
    private String resourceType;

    @Column(nullable = false, length = 100)
    private String resourceId;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(columnDefinition = "json")
    private JsonNode payload;

    @Column(nullable = false)
    private Instant timestamp;

    @Column(length = 64, unique = true)
    private String previousHash;

    @Column(length = 64, nullable = false)
    private String contentHash;

    @Column(length = 64)
    private String recordHash;

    @Column(name = "redaction_digest", length = 64)
    private String redactionDigest;


    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    @Builder.Default
    private AuditRecordStatus status = AuditRecordStatus.ACTIVE;

    @CreationTimestamp
    @Column(nullable = false, updatable = false)
    private Instant createdAt;
}
