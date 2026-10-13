package com.vpbank.dcp.core.port.out.pending;

public interface PendingTokenCryptography {
    PreparedPendingToken issue(PendingTotpLogin pending);
}
