package com.vpbank.dcp.core.application.mfa;

import com.vpbank.dcp.core.domain.security.Digest32;
import com.vpbank.dcp.core.port.in.mfa.CompleteTotpLoginUseCase;
import com.vpbank.dcp.core.port.in.mfa.TotpLoginCommand;
import com.vpbank.dcp.core.port.in.mfa.TotpLoginResult;
import com.vpbank.dcp.core.port.in.session.IssueLoginSessionUseCase;
import com.vpbank.dcp.core.port.in.session.LoginConfirmation;
import com.vpbank.dcp.core.port.in.session.SessionLoginEvidence;
import com.vpbank.dcp.core.port.in.session.SessionLoginResult;
import com.vpbank.dcp.core.port.out.pending.PendingTotpLogin;
import com.vpbank.dcp.core.port.out.pending.PendingTotpUnavailableException;
import com.vpbank.dcp.core.port.out.session.SessionKeyBindings;
import java.util.Objects;

/** Consumes the accepted challenge once before attempting guarded session publication. */
public final class CompleteTotpLoginService implements CompleteTotpLoginUseCase {
    private final AdmitPendingTotpService admission;
    private final CheckPendingTotpOwnerService owners;
    private final CheckTotpChallengeService codes;
    private final IssueLoginSessionUseCase sessions;

    public CompleteTotpLoginService(AdmitPendingTotpService admission,
                                    CheckPendingTotpOwnerService owners,
                                    CheckTotpChallengeService codes,
                                    IssueLoginSessionUseCase sessions) {
        this.admission = Objects.requireNonNull(admission);
        this.owners = Objects.requireNonNull(owners);
        this.codes = Objects.requireNonNull(codes);
        this.sessions = Objects.requireNonNull(sessions);
    }

    @Override
    public TotpLoginResult complete(TotpLoginCommand command) {
        Objects.requireNonNull(command);
        PendingTotpAdmission admitted = admission.admit(command);
        if (admitted instanceof PendingTotpAdmission.Rejected) {
            return new TotpLoginResult.Rejected();
        }
        if (admitted instanceof PendingTotpAdmission.Unavailable) {
            return new TotpLoginResult.Unavailable();
        }
        PendingTotpLogin pending = ((PendingTotpAdmission.Admitted) admitted).pending();
        PendingTotpOwner owner = owners.current(pending, command.now());
        if (owner instanceof PendingTotpOwner.Rejected) {
            return new TotpLoginResult.Rejected();
        }
        if (owner instanceof PendingTotpOwner.Unavailable) {
            return new TotpLoginResult.Unavailable();
        }
        TotpChallengeResult checked = codes.check(pending, command.encryptedCode(), command.now());
        if (checked == TotpChallengeResult.UNAVAILABLE) {
            return new TotpLoginResult.Unavailable();
        }
        if (checked != TotpChallengeResult.ACCEPTED) {
            return new TotpLoginResult.Rejected();
        }
        try {
            if (!admission.consume(command.pendingToken(), pending)) {
                return new TotpLoginResult.Rejected();
            }
        } catch (PendingTotpUnavailableException failure) {
            return new TotpLoginResult.Unavailable();
        }
        PendingTotpOwner.Current current = (PendingTotpOwner.Current) owner;
        SessionKeyBindings keys = new SessionKeyBindings(Digest32.fromBase64Url(
                pending.keys().requestKeyJkt()), pending.keys().requestPublicJwk(),
                pending.keys().responsePublicJwk(), Digest32.fromBase64Url(pending.keys().deviceKeyJkt()));
        SessionLoginEvidence evidence = new SessionLoginEvidence(pending.identity().customerId(),
                current.customer(), current.device(), keys, pending.versions().generation(),
                LoginConfirmation.DEVICE_TOTP);
        SessionLoginResult issued = sessions.issue(pending.identity().operationId(), command.now(), evidence);
        return issued instanceof SessionLoginResult.Active active
                ? new TotpLoginResult.Active(active.session())
                : new TotpLoginResult.Unavailable();
    }
}
