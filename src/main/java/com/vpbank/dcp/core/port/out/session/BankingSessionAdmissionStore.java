package com.vpbank.dcp.core.port.out.session;

import java.util.Optional;

public interface BankingSessionAdmissionStore {
    Optional<BankingSessionLookup> lookup(String exactToken);
    SessionAdmissionResult admit(BankingSessionLookup lookup, VerifiedSessionProof proof,
                                 boolean eligibleActivity);
}
