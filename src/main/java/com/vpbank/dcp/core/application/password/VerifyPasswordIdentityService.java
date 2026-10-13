package com.vpbank.dcp.core.application.password;

import com.vpbank.dcp.core.port.in.password.PasswordLoginCommand;
import com.vpbank.dcp.core.port.out.keycloak.DirectGrantPasswordVerifier;
import com.vpbank.dcp.core.port.out.keycloak.KeycloakVerificationUnavailableException;
import com.vpbank.dcp.core.port.out.keycloak.PasswordVerificationOutcome;
import java.util.Objects;

/** One Direct Grant attempt, followed by Customer eligibility and immutable owner acceptance. */
public final class VerifyPasswordIdentityService {
    private final DirectGrantPasswordVerifier passwords;
    private final ConfirmPasswordLoginOwnerService owners;

    public VerifyPasswordIdentityService(DirectGrantPasswordVerifier passwords,
                                         ConfirmPasswordLoginOwnerService owners) {
        this.passwords = Objects.requireNonNull(passwords);
        this.owners = Objects.requireNonNull(owners);
    }

    public PasswordIdentityResult verify(PasswordLoginCommand command) {
        Objects.requireNonNull(command);
        PasswordVerificationOutcome outcome;
        try {
            outcome = passwords.verify(command.credential());
        } catch (KeycloakVerificationUnavailableException failure) {
            // The request may have reached Keycloak. Never dispatch this password again.
            return new PasswordIdentityResult.Unavailable();
        }
        if (outcome instanceof PasswordVerificationOutcome.Rejected) {
            return new PasswordIdentityResult.Rejected();
        }
        PasswordVerificationOutcome.Verified verified = (PasswordVerificationOutcome.Verified) outcome;
        PasswordLoginOwnerResult owner = owners.confirmOwner(verified.identity(), command.now());
        if (owner instanceof PasswordLoginOwnerResult.Accepted accepted) {
            return new PasswordIdentityResult.Verified(accepted.subjectId(), accepted.customer());
        }
        return owner instanceof PasswordLoginOwnerResult.Unavailable
                ? new PasswordIdentityResult.Unavailable()
                : new PasswordIdentityResult.Rejected();
    }
}
