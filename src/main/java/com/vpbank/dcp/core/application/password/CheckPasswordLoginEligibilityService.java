package com.vpbank.dcp.core.application.password;

import com.vpbank.dcp.core.domain.device.TrustedDeviceRoute;
import com.vpbank.dcp.core.port.in.password.PasswordLoginCommand;
import com.vpbank.dcp.core.port.out.password.PasswordCredentialRecordResult;
import com.vpbank.dcp.core.port.out.password.PasswordOperationRepository;
import java.util.Objects;

/** Checks identity and device eligibility, recording unavailable MFA before session activation. */
public final class CheckPasswordLoginEligibilityService {

    private final VerifyPasswordLoginIdentityService credentials;
    private final ResolveTrustedDeviceRouteService devices;
    private final PasswordOperationRepository operations;

    public CheckPasswordLoginEligibilityService(VerifyPasswordLoginIdentityService credentials,
                                     ResolveTrustedDeviceRouteService devices,
                                     PasswordOperationRepository operations) {
        this.credentials = Objects.requireNonNull(credentials, "credentials");
        this.devices = Objects.requireNonNull(devices, "devices");
        this.operations = Objects.requireNonNull(operations, "operations");
    }

    public PasswordLoginEligibilityResult checkEligibility(PasswordLoginCommand command) {
        PasswordLoginIdentityResult credential = credentials.verifyIdentity(command);
        if (credential instanceof PasswordLoginIdentityResult.MfaUnavailable) {
            return new PasswordLoginEligibilityResult.MfaUnavailable();
        }
        if (credential instanceof PasswordLoginIdentityResult.Rejected) {
            return new PasswordLoginEligibilityResult.Rejected();
        }
        if (credential instanceof PasswordLoginIdentityResult.Conflict) {
            return new PasswordLoginEligibilityResult.Conflict();
        }
        if (credential instanceof PasswordLoginIdentityResult.AuthorityClosed) {
            return new PasswordLoginEligibilityResult.AuthorityClosed();
        }
        if (!(credential instanceof PasswordLoginIdentityResult.Verified verified)) {
            return new PasswordLoginEligibilityResult.Processing();
        }

        TrustedDeviceRoute route = devices.resolve(command.operation().operationId(),
                verified.subjectId(), command.operation().appId(), command.now());
        if (route == TrustedDeviceRoute.LAST_TRUSTED) {
            return new PasswordLoginEligibilityResult.LastTrusted(verified.subjectId());
        }
        if (route == TrustedDeviceRoute.REJECTED) {
            return new PasswordLoginEligibilityResult.Rejected();
        }
        PasswordCredentialRecordResult saved = operations.recordMfaUnavailable(
                command.operation().operationId(), route);
        return saved == PasswordCredentialRecordResult.NOT_RECORDABLE
                ? new PasswordLoginEligibilityResult.Processing()
                : new PasswordLoginEligibilityResult.MfaUnavailable();
    }
}
