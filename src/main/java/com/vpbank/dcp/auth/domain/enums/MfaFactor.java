package com.vpbank.dcp.auth.domain.enums;

/** The factors Auth may ask the MFA service for (DD 20 §5). The receipt names the factor set that passed. */
public enum MfaFactor {
    FACE,
    OTP
}
