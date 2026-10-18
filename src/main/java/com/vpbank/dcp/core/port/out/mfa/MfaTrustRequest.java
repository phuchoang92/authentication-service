package com.vpbank.dcp.core.port.out.mfa;

import com.vpbank.dcp.core.domain.customer.CustomerNumber;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/**
 * Binds one MFA transaction to exactly one trust attempt. Auth sends the Customer number, never
 * its internal subject ID, device ID or any key. The same values are sent again on check.
 */
public record MfaTrustRequest(UUID authOperationId, CustomerNumber customerNumber, String channel,
                              Instant notAfter) {
    public MfaTrustRequest {
        Objects.requireNonNull(authOperationId, "authOperationId");
        Objects.requireNonNull(customerNumber, "customerNumber");
        Objects.requireNonNull(notAfter, "notAfter");
        if (channel == null || channel.isBlank() || channel.length() > 64) {
            throw new InvalidMfaTransactionException();
        }
    }
}
