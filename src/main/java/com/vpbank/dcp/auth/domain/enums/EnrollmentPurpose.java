package com.vpbank.dcp.auth.domain.enums;

/** PURPOSE of an enrollment. Only device trust exists so far; later flows reuse the table. */
public enum EnrollmentPurpose {
    /** Primary enrollment: the device proves its key and passes FACE itself (slice 5). */
    TRUST_DEVICE,
    /** A new device trusted and made primary by the current primary device through a QR token (slice 6). */
    TRUST_DEVICE_APPROVAL
}
