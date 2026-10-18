package com.vpbank.dcp.core.port.out.mfa;

import java.util.Objects;

/** Re-checks the transaction started for {@code request}; the receipt must echo all of it. */
public record MfaTrustCheck(String mfaTransactionId, MfaTrustRequest request) {
    public MfaTrustCheck {
        Objects.requireNonNull(request, "request");
        if (mfaTransactionId == null || !mfaTransactionId.matches("[A-Za-z0-9_-]{22,64}")) {
            throw new InvalidMfaTransactionException();
        }
    }
}
