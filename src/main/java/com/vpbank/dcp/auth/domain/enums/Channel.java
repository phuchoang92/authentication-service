package com.vpbank.dcp.auth.domain.enums;

/** Where the customer logs in from. Stored in the session so the BFF can scope what it mints. */
public enum Channel {
    MOBILE,
    WEB
}
