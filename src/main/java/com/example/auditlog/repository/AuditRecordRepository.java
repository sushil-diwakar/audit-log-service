package com.example.auditlog.repository;

import com.example.auditlog.entity.AuditRecord;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.UUID;

@Repository
public interface AuditRecordRepository extends JpaRepository<AuditRecord, UUID> {

    Page<AuditRecord> findByActorId(String actorId, Pageable pageable);

    Page<AuditRecord> findByResourceTypeAndResourceId(String resourceType, String resourceId, Pageable pageable);

    Page<AuditRecord> findByEventType(String eventType, Pageable pageable);

    Page<AuditRecord> findByTimestampBetween(Instant start, Instant end, Pageable pageable);
}
