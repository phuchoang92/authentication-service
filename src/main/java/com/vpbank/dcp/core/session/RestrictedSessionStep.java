package com.vpbank.dcp.core.session;

/** init → verify → confirm, strictly in order. */
public enum RestrictedSessionStep {
    /** Opened by login; init has not run. */
    OPEN,
    /** init ran: Ksrv and the challenge exist, verify has not passed. */
    KEY_EXCHANGE,
    /** verify passed and the MFA transaction exists; only confirm remains. */
    MFA
}
