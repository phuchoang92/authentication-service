package com.vpbank.dcp.auth.domain.enums;

/** PRIMARY_MODE: how the current primary device was chosen. */
public enum PrimaryMode {
    /** The customer's first device, trusted on its first password login (phase 3). */
    DIRECT_PRIMARY,
    /** Key proof + FACE through the enrollment flow (phase 4). */
    FACE_CONFIRMED,
    /** Reserved: approval by an existing device. */
    OLD_DEVICE_APPROVAL
}
