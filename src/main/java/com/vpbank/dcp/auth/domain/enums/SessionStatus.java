package com.vpbank.dcp.auth.domain.enums;

/**
 * ACTIVE sessions admit business requests. NEED_TRUSTED_DEVICE is a restricted session: the
 * password was right but the device is not the trusted primary, so only the trusted-device
 * routes and logout are allowed (DD 20 §3). ENDED ones never come back.
 */
public enum SessionStatus {
    ACTIVE,
    NEED_TRUSTED_DEVICE,
    ENDED;

    /** Admits ordinary (business) requests. */
    public boolean full() {
        return this == ACTIVE;
    }

    public boolean live() {
        return this != ENDED;
    }
}
