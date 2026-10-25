package com.vpbank.dcp.core.session;

/** Locked Customer row facts that decide whether a session may still be published. */
public record StoredCustomerSecurity(boolean eligible, long statusVersion) { }
