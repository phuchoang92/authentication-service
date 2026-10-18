package com.vpbank.dcp.core.application.mfa;

import com.vpbank.dcp.core.domain.security.Digest32;
import com.vpbank.dcp.core.port.in.mfa.ConfirmLoginCommand;
import com.vpbank.dcp.core.port.in.mfa.ConfirmLoginResult;
import com.vpbank.dcp.core.port.in.mfa.ConfirmLoginUseCase;
import com.vpbank.dcp.core.port.in.session.IssueLoginSessionUseCase;
import com.vpbank.dcp.core.port.in.session.LoginConfirmation;
import com.vpbank.dcp.core.port.in.session.SessionLoginEvidence;
import com.vpbank.dcp.core.port.in.session.SessionLoginResult;
import com.vpbank.dcp.core.port.out.mfa.MfaCheck;
import com.vpbank.dcp.core.port.out.mfa.MfaCheckResult;
import com.vpbank.dcp.core.port.out.mfa.MfaTransactions;
import com.vpbank.dcp.core.port.out.mfa.MfaUnavailableException;
import com.vpbank.dcp.core.port.out.pending.PendingMfaLogin;
import com.vpbank.dcp.core.port.out.pending.PendingMfaLoginUnavailableException;
import com.vpbank.dcp.core.port.out.session.SessionKeyBindings;
import java.util.Objects;

/**
 * Completes a login whose MFA was elevated at the MFA service.
 *
 * <p>Auth never trusts the App's word that MFA passed: it re-checks the transaction it started,
 * re-reads the owner and device, and only then consumes the pending login exactly once.
 */
public final class ConfirmLoginService implements ConfirmLoginUseCase {
    private final AdmitPendingLoginService admission;
    private final CheckPendingLoginOwnerService owners;
    private final MfaTransactions mfa;
    private final IssueLoginSessionUseCase sessions;

    public ConfirmLoginService(AdmitPendingLoginService admission,
                               CheckPendingLoginOwnerService owners, MfaTransactions mfa,
                               IssueLoginSessionUseCase sessions) {
        this.admission = Objects.requireNonNull(admission);
        this.owners = Objects.requireNonNull(owners);
        this.mfa = Objects.requireNonNull(mfa);
        this.sessions = Objects.requireNonNull(sessions);
    }

    @Override
    public ConfirmLoginResult confirm(ConfirmLoginCommand command) {
        Objects.requireNonNull(command);
        PendingLoginAdmission admitted = admission.admit(command);
        if (admitted instanceof PendingLoginAdmission.Rejected) {
            return new ConfirmLoginResult.Rejected();
        }
        if (admitted instanceof PendingLoginAdmission.Unavailable) {
            return new ConfirmLoginResult.Unavailable();
        }
        PendingMfaLogin pending = ((PendingLoginAdmission.Admitted) admitted).pending();
        PendingLoginOwner owner = owners.current(pending, command.now());
        if (owner instanceof PendingLoginOwner.Rejected) {
            return new ConfirmLoginResult.Rejected();
        }
        if (owner instanceof PendingLoginOwner.Unavailable) {
            return new ConfirmLoginResult.Unavailable();
        }
        if (!command.now().isBefore(pending.mfa().expiresAt())) {
            return new ConfirmLoginResult.Rejected();
        }
        MfaCheckResult checked;
        try {
            checked = mfa.check(new MfaCheck(pending.mfa().transactionId(),
                    pending.identity().operationId(), pending.identity().owner(), command.now()));
        } catch (MfaUnavailableException failure) {
            return new ConfirmLoginResult.Unavailable();
        }
        if (checked != MfaCheckResult.PASSED) {
            // Leave the pending login intact: the App can elevate at the MFA service and retry.
            return new ConfirmLoginResult.MfaNotPassed();
        }
        try {
            if (!admission.consume(command.pendingToken(), pending)) {
                return new ConfirmLoginResult.Rejected();
            }
        } catch (PendingMfaLoginUnavailableException failure) {
            return new ConfirmLoginResult.Unavailable();
        }
        PendingLoginOwner.Current current = (PendingLoginOwner.Current) owner;
        SessionKeyBindings keys = new SessionKeyBindings(Digest32.fromBase64Url(
                pending.keys().requestKeyJkt()), pending.keys().requestPublicJwk(),
                pending.keys().responsePublicJwk(), Digest32.fromBase64Url(pending.keys().deviceKeyJkt()));
        SessionLoginEvidence evidence = new SessionLoginEvidence(pending.identity().owner(),
                current.customer(), current.device(), keys, pending.versions().generation(),
                LoginConfirmation.MFA_CONFIRMED);
        SessionLoginResult issued = sessions.issue(pending.identity().operationId(), command.now(), evidence);
        return issued instanceof SessionLoginResult.Active active
                ? new ConfirmLoginResult.Active(active.session())
                : new ConfirmLoginResult.Unavailable();
    }
}
