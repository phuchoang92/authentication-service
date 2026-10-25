package com.vpbank.dcp.core.customer;

public enum CustomerStateDecision {
    ACCEPT,
    STALE,
    CONFLICT,
    BLOCK_WATERMARK_ADVANCED
}
