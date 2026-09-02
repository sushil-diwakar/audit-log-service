package com.example.auditlog.enums;

public enum ChainViolationType {
    MISSING_GENESIS,
    MULTIPLE_GENESIS,
    RECORD_HASH_MISMATCH,
    BROKEN_PREVIOUS_LINK,
    FORK_DETECTED,
    DISCONNECTED_RECORD,
    CYCLE_DETECTED
}
