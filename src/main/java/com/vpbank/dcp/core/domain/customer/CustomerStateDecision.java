package com.vpbank.dcp.core.domain.customer;

public enum CustomerStateDecision {
    ACCEPT,
    STALE,
    CONFLICT,
    BLOCK_WATERMARK_ADVANCED
}
