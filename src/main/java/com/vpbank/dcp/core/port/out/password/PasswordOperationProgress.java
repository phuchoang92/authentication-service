package com.vpbank.dcp.core.port.out.password;

/** Durable progress of one password operation, never a banking-session result. */
public enum PasswordOperationProgress {
    RESERVED,
    DISPATCHED,
    VERIFIED,
    UNCERTAIN,
    CONFIRMED,
    MFA_UNAVAILABLE,
    REJECTED,
    COMPLETED,
    MISSING
}
