package com.vpbank.dcp.auth.domain.model;

/**
 * STATUS of a TRUSTED_DEVICE row. PENDING, ACTIVE and SUSPENDED are live (LIVE_SLOT = 1);
 * EXPIRED and REVOKED are history.
 */
public enum DeviceStatus {
    PENDING,
    ACTIVE,
    SUSPENDED,
    EXPIRED,
    REVOKED;

    public boolean live() {
        return this == PENDING || this == ACTIVE || this == SUSPENDED;
    }
}
