package com.vpbank.dcp.core.application.session;

import com.vpbank.dcp.core.port.in.session.AdmitBankingRequest;
import com.vpbank.dcp.core.port.out.session.BankingSessionAdmissionStore;
import com.vpbank.dcp.core.port.out.session.SessionAdmissionResult;
import com.vpbank.dcp.core.port.out.session.SessionProofVerifier;
import com.vpbank.dcp.core.port.out.session.CustomerContextSigner;
import com.vpbank.dcp.core.port.out.session.InvalidSessionProofException;
import java.time.Clock;
import java.util.Objects;

/** A pre-read is followed by proof verification and one atomic online admission. */
public final class BankingAdmissionService implements AdmitBankingRequest {
    private final BankingSessionAdmissionStore sessions;
    private final SessionProofVerifier proofs;
    private final Clock clock;
    private final CustomerContextSigner contexts;

    public BankingAdmissionService(BankingSessionAdmissionStore sessions,
                                   SessionProofVerifier proofs, CustomerContextSigner contexts,
                                   Clock clock) {
        this.sessions = Objects.requireNonNull(sessions);
        this.proofs = Objects.requireNonNull(proofs);
        this.clock = Objects.requireNonNull(clock);
        this.contexts = Objects.requireNonNull(contexts);
    }

    @Override
    public BankingAdmissionDecision admit(BankingAdmissionCommand command) {
        if (!"ACCOUNT_READ".equals(command.targetAction())
                || !"account-service".equals(command.audience())) {
            return new BankingAdmissionDecision.Denied();
        }
        var lookup = sessions.lookup(command.exactToken()).orElse(null);
        if (lookup == null) {
            return new BankingAdmissionDecision.Denied();
        }
        var proof = verifiedProof(command, lookup);
        if (proof == null) {
            return new BankingAdmissionDecision.Denied();
        }
        SessionAdmissionResult outcome = sessions.admit(lookup, proof, true);
        if (outcome instanceof SessionAdmissionResult.Admitted admitted) {
            var contextExpiry = clock.instant().plusSeconds(30);
            if (contextExpiry.isAfter(admitted.deadlines().idleExpiresAt())) {
                contextExpiry = admitted.deadlines().idleExpiresAt();
            }
            if (contextExpiry.isAfter(admitted.deadlines().absoluteExpiresAt())) {
                contextExpiry = admitted.deadlines().absoluteExpiresAt();
            }
            String context = contexts.sign(lookup.subjectId(), lookup.bindingId(),
                    lookup.appId(), command.audience(), command.targetAction(),
                    contextExpiry);
            return new BankingAdmissionDecision.Admitted(context, proof.nonce(),
                    admitted.deadlines());
        }
        if (outcome instanceof SessionAdmissionResult.NonceRequired required) {
            return new BankingAdmissionDecision.NonceRequired(required.nonce());
        }
        if (outcome instanceof SessionAdmissionResult.AuthorityClosed) {
            return new BankingAdmissionDecision.Unavailable();
        }
        return new BankingAdmissionDecision.Denied();
    }

    private com.vpbank.dcp.core.port.out.session.VerifiedSessionProof verifiedProof(
            BankingAdmissionCommand command,
            com.vpbank.dcp.core.port.out.session.BankingSessionLookup lookup) {
        try {
            return proofs.verify(command.exactToken(), command.dpopProof(), command.method(),
                    command.externalUri(), lookup, clock.instant());
        } catch (InvalidSessionProofException invalid) {
            return null;
        }
    }
}
