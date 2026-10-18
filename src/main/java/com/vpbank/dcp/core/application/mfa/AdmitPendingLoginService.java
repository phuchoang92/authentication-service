package com.vpbank.dcp.core.application.mfa;

import com.vpbank.dcp.core.domain.security.Digest32;
import com.vpbank.dcp.core.domain.security.RequestKeyThumbprint;
import com.vpbank.dcp.core.port.in.mfa.ConfirmLoginCommand;
import com.vpbank.dcp.core.port.out.pending.PendingMfaLogin;
import com.vpbank.dcp.core.port.out.pending.PendingMfaLoginStore;
import com.vpbank.dcp.core.port.out.pending.PendingMfaLoginUnavailableException;
import com.vpbank.dcp.core.port.out.replay.ReplayAttempt;
import com.vpbank.dcp.core.port.out.replay.ReplayAuthorityUnavailableException;
import com.vpbank.dcp.core.port.out.replay.ReplayProtection;
import com.vpbank.dcp.core.port.out.replay.ReplayReservation;
import com.vpbank.dcp.core.port.out.security.VerifiedDpopProof;
import com.vpbank.dcp.core.port.out.session.SessionTokenLookup;
import java.util.Objects;

/** Requires the exact challenge, Kreq and a fresh shared DPoP replay reservation. */
public final class AdmitPendingLoginService {
    private final PendingMfaLoginStore pendingLogins;
    private final ReplayProtection replay;

    public AdmitPendingLoginService(PendingMfaLoginStore pendingLogins, ReplayProtection replay) {
        this.pendingLogins = Objects.requireNonNull(pendingLogins);
        this.replay = Objects.requireNonNull(replay);
    }

    public PendingLoginAdmission admit(ConfirmLoginCommand command) {
        Objects.requireNonNull(command);
        PendingMfaLogin pending;
        try {
            pending = pendingLogins.find(command.pendingToken()).orElse(null);
        } catch (PendingMfaLoginUnavailableException failure) {
            return new PendingLoginAdmission.Unavailable();
        }
        if (pending == null || !pending.challenge().challengeId().equals(command.challengeId())
                || !command.now().isBefore(pending.challenge().expiresAt())
                || command.dpop().verification() != VerifiedDpopProof.Verification.VERIFIED
                || !command.dpop().requestKey().equals(new RequestKeyThumbprint(
                        Digest32.fromBase64Url(pending.keys().requestKeyJkt())))) {
            return new PendingLoginAdmission.Rejected();
        }
        try {
            ReplayReservation reserved = replay.reserve(new ReplayAttempt(command.dpop().requestKey(),
                    command.dpop().proofIdDigest(), pending.versions().generation()));
            if (reserved == ReplayReservation.RESERVED) {
                return new PendingLoginAdmission.Admitted(pending);
            }
            return reserved == ReplayReservation.REPLAYED
                    ? new PendingLoginAdmission.Rejected()
                    : new PendingLoginAdmission.Unavailable();
        } catch (ReplayAuthorityUnavailableException failure) {
            return new PendingLoginAdmission.Unavailable();
        }
    }

    public boolean consume(SessionTokenLookup token, PendingMfaLogin admitted) {
        return admitted.equals(pendingLogins.consume(token).orElse(null));
    }
}
