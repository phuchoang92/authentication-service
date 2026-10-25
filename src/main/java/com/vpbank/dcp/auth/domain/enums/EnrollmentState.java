package com.vpbank.dcp.auth.domain.enums;

/**
 * STATE of an enrollment along init → verify → confirm (DD 20 §4): KEY_EXCHANGE after init,
 * MFA_REQUIRED after the key proof, then COMPLETED, or FAILED / EXPIRED.
 */
public enum EnrollmentState {
    KEY_EXCHANGE,
    MFA_REQUIRED,
    COMPLETED,
    FAILED,
    EXPIRED;

    public boolean open() {
        return this == KEY_EXCHANGE || this == MFA_REQUIRED;
    }
}
