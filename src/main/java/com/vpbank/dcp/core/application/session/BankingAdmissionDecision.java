package com.vpbank.dcp.core.application.session;

import com.vpbank.dcp.core.domain.session.SessionDeadlines;
import java.util.UUID;

public sealed interface BankingAdmissionDecision {
    record Admitted(String customerContext, String dpopNonce,
                    SessionDeadlines deadlines) implements BankingAdmissionDecision { }
    record NonceRequired(String nonce) implements BankingAdmissionDecision { }
    record Denied() implements BankingAdmissionDecision { }
    record Unavailable() implements BankingAdmissionDecision { }
}
