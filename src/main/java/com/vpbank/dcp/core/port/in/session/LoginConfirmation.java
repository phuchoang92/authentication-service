package com.vpbank.dcp.core.port.in.session;

/** Which verified factors allow this login to use the confirmed trusted binding. */
public enum LoginConfirmation {
    PRIMARY_PASSWORD,
    MFA_CONFIRMED,
    FULL_DEVICE_MFA
}
