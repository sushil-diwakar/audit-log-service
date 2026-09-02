package com.example.auditlog.repository;

import com.example.auditlog.entity.AuditRecord;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.stereotype.Repository;

import org.springframework.data.jpa.repository.Query;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface AuditRecordRepository extends JpaRepository<AuditRecord, UUID>, JpaSpecificationExecutor<AuditRecord> {
    
    @Query("SELECT a FROM AuditRecord a WHERE NOT EXISTS (SELECT 1 FROM AuditRecord b WHERE b.previousHash = a.recordHash)")
    Optional<AuditRecord> findCurrentChainHead();

    @org.springframework.data.jpa.repository.Modifying
    @Query("UPDATE AuditRecord a SET a.status = 'ARCHIVED' WHERE a.timestamp < :cutoff AND a.status = 'ACTIVE'")
    int archiveOldRecords(@org.springframework.data.repository.query.Param("cutoff") java.time.Instant cutoff);
}
