package com.vpbank.dcp.core.port.in.session;

import com.vpbank.dcp.core.domain.session.SessionDeadlines;

public sealed interface BankingRequestAdmissionResult {
    record Admitted(String customerContext, String dpopNonce,
                    SessionDeadlines deadlines) implements BankingRequestAdmissionResult {
    }

    record NonceRequired(String nonce) implements BankingRequestAdmissionResult {
    }

    record Denied() implements BankingRequestAdmissionResult {
    }

    record Unavailable() implements BankingRequestAdmissionResult {
    }
}
