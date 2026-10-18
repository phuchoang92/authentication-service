package com.vpbank.dcp.core.port.out.mfa;

import com.vpbank.dcp.core.domain.customer.CustomerNumber;
import com.vpbank.dcp.core.domain.customer.SubjectId;
import com.vpbank.dcp.core.domain.device.BindingId;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/** What the MFA service needs to open a login transaction. Carries no credential material. */
public record MfaLoginRequest(UUID operationId, SubjectId owner, CustomerNumber customerNumber,
                              BindingId bindingId, String channel, Instant notAfter) {
    public MfaLoginRequest {
        Objects.requireNonNull(operationId, "operationId");
        Objects.requireNonNull(owner, "owner");
        Objects.requireNonNull(customerNumber, "customerNumber");
        Objects.requireNonNull(bindingId, "bindingId");
        Objects.requireNonNull(notAfter, "notAfter");
        if (channel == null || channel.isBlank() || channel.length() > 64) {
            throw new InvalidMfaTransactionException();
        }
    }
}
