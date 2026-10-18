package com.vpbank.dcp.core.port.out.session;

/** Locked Customer row facts that decide whether a session may still be published. */
public record StoredCustomerSecurity(boolean eligible, long statusVersion) { }
