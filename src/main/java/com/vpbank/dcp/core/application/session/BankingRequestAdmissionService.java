package com.vpbank.dcp.core.application.session;

import com.vpbank.dcp.core.domain.session.SessionDeadlines;
import com.vpbank.dcp.core.port.in.session.BankingRequestAdmissionCommand;
import com.vpbank.dcp.core.port.in.session.BankingRequestAdmissionResult;
import com.vpbank.dcp.core.port.in.session.BankingRequestAdmissionUseCase;
import com.vpbank.dcp.core.port.out.session.*;

import java.time.Clock;
import java.util.Objects;

/**
 * A pre-read is followed by proof verification and one atomic online admission.
 */
public final class BankingRequestAdmissionService implements BankingRequestAdmissionUseCase {
    private final BankingSessionAdmissionStore sessions;
    private final SessionProofVerifier proofs;
    private final Clock clock;
    private final CustomerContextSigner contexts;

    public BankingRequestAdmissionService(BankingSessionAdmissionStore sessions,
                                   SessionProofVerifier proofs, CustomerContextSigner contexts,
                                   Clock clock) {
        this.sessions = Objects.requireNonNull(sessions);
        this.proofs = Objects.requireNonNull(proofs);
        this.clock = Objects.requireNonNull(clock);
        this.contexts = Objects.requireNonNull(contexts);
    }

    @Override
    public BankingRequestAdmissionResult admit(BankingRequestAdmissionCommand command) {
        if (!"ACCOUNT_READ".equals(command.targetAction())
                || !"account-service".equals(command.audience())) {
            return new BankingRequestAdmissionResult.Denied();
        }
        var lookup = sessions.lookup(command.exactToken()).orElse(null);
        if (lookup == null) {
            return new BankingRequestAdmissionResult.Denied();
        }
        var proof = verifiedProof(command, lookup);
        if (proof == null) {
            return new BankingRequestAdmissionResult.Denied();
        }
        SessionAdmissionResult outcome = sessions.admit(lookup, proof, true);
        if (outcome instanceof SessionAdmissionResult.Admitted(SessionDeadlines deadlines)) {
            var contextExpiry = clock.instant().plusSeconds(30);
            if (contextExpiry.isAfter(deadlines.idleExpiresAt())) {
                contextExpiry = deadlines.idleExpiresAt();
            }
            if (contextExpiry.isAfter(deadlines.absoluteExpiresAt())) {
                contextExpiry = deadlines.absoluteExpiresAt();
            }
            String context = contexts.sign(lookup.subjectId(),
                    lookup.bindingId(),
                    lookup.appId(),
                    command.audience(),
                    command.targetAction(),
                    contextExpiry);
            return new BankingRequestAdmissionResult.Admitted(context, proof.nonce(), deadlines);
        }
        if (outcome instanceof SessionAdmissionResult.NonceRequired(String nonce)) {
            return new BankingRequestAdmissionResult.NonceRequired(nonce);
        }
        if (outcome instanceof SessionAdmissionResult.AuthorityClosed) {
            return new BankingRequestAdmissionResult.Unavailable();
        }
        return new BankingRequestAdmissionResult.Denied();
    }

    private VerifiedSessionProof verifiedProof(BankingRequestAdmissionCommand command, BankingSessionLookup lookup) {
        try {
            return proofs.verify(command.exactToken(),
                    command.dpopProof(),
                    command.method(),
                    command.externalUri(),
                    lookup,
                    clock.instant());
        } catch (InvalidSessionProofException invalid) {
            return null;
        }
    }
}
