package com.vpbank.dcp.auth.infrastructure.adapter.out.valkey;

/**
 * Key factory for the IDs of assertions already used once: one per kind of assertion, so BFF assertions and
 * service client assertions never share a key space. No I/O, no clock (RK02/RK10).
 */
public interface UsedAssertionKeys {
    String forAssertionId(String assertionId);
}
