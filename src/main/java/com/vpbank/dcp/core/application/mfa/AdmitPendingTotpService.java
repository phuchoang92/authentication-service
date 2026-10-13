package com.vpbank.dcp.core.application.mfa;

import com.vpbank.dcp.core.domain.security.Digest32;
import com.vpbank.dcp.core.domain.security.RequestKeyThumbprint;
import com.vpbank.dcp.core.port.in.mfa.TotpLoginCommand;
import com.vpbank.dcp.core.port.out.pending.PendingTotpLogin;
import com.vpbank.dcp.core.port.out.pending.PendingTotpStore;
import com.vpbank.dcp.core.port.out.pending.PendingTotpUnavailableException;
import com.vpbank.dcp.core.port.out.replay.ReplayAttempt;
import com.vpbank.dcp.core.port.out.replay.ReplayAuthorityUnavailableException;
import com.vpbank.dcp.core.port.out.replay.ReplayProtection;
import com.vpbank.dcp.core.port.out.replay.ReplayReservation;
import com.vpbank.dcp.core.port.out.security.VerifiedDpopProof;
import com.vpbank.dcp.core.port.out.session.SessionTokenLookup;
import java.util.Objects;

/** Requires the exact challenge, Kreq and a fresh shared DPoP replay reservation. */
public final class AdmitPendingTotpService {
    private final PendingTotpStore pendingLogins;
    private final ReplayProtection replay;

    public AdmitPendingTotpService(PendingTotpStore pendingLogins, ReplayProtection replay) {
        this.pendingLogins = Objects.requireNonNull(pendingLogins);
        this.replay = Objects.requireNonNull(replay);
    }

    public PendingTotpAdmission admit(TotpLoginCommand command) {
        Objects.requireNonNull(command);
        PendingTotpLogin pending;
        try {
            pending = pendingLogins.find(command.pendingToken()).orElse(null);
        } catch (PendingTotpUnavailableException failure) {
            return new PendingTotpAdmission.Unavailable();
        }
        if (pending == null || !pending.challenge().challengeId().equals(command.challengeId())
                || !command.now().isBefore(pending.challenge().expiresAt())
                || command.dpop().verification() != VerifiedDpopProof.Verification.VERIFIED
                || !command.dpop().requestKey().equals(new RequestKeyThumbprint(
                        Digest32.fromBase64Url(pending.keys().requestKeyJkt())))) {
            return new PendingTotpAdmission.Rejected();
        }
        try {
            ReplayReservation reserved = replay.reserve(new ReplayAttempt(command.dpop().requestKey(),
                    command.dpop().proofIdDigest(), pending.versions().generation()));
            if (reserved == ReplayReservation.RESERVED) {
                return new PendingTotpAdmission.Admitted(pending);
            }
            return reserved == ReplayReservation.REPLAYED
                    ? new PendingTotpAdmission.Rejected()
                    : new PendingTotpAdmission.Unavailable();
        } catch (ReplayAuthorityUnavailableException failure) {
            return new PendingTotpAdmission.Unavailable();
        }
    }

    public boolean consume(SessionTokenLookup token, PendingTotpLogin admitted) {
        return admitted.equals(pendingLogins.consume(token).orElse(null));
    }
}
