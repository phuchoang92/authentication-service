package com.vpbank.dcp.auth.domain.enums;

/**
 * STATE of an enrollment along init → verify → confirm (DD 20 §4): KEY_EXCHANGE after init,
 * MFA_REQUIRED after the key proof, then COMPLETED, or FAILED / EXPIRED.
 */
public enum EnrollmentState {
    KEY_EXCHANGE,
    MFA_REQUIRED,
    /** Approval path: the request is listed on the primary device until it approves or the window ends. */
    WAITING_APPROVAL,
    /** Approval path: the primary passed MFA and holds the QR token; the new device must claim it. */
    WAITING_AUTHORIZATION,
    COMPLETED,
    FAILED,
    EXPIRED;

    public boolean open() {
        return this == KEY_EXCHANGE || this == MFA_REQUIRED || this == WAITING_APPROVAL || this == WAITING_AUTHORIZATION;
    }
}
