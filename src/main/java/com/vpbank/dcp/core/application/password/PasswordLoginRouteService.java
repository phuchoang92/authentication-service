package com.vpbank.dcp.core.application.password;

import com.vpbank.dcp.core.domain.device.TrustedDeviceRoute;
import com.vpbank.dcp.core.port.in.password.PasswordLoginCommand;
import com.vpbank.dcp.core.port.out.password.PasswordCredentialRecordResult;
import com.vpbank.dcp.core.port.out.password.PasswordOperationStore;
import java.util.Objects;

/** Freezes unsupported MFA routes without creating a challenge or a banking token. */
public final class PasswordLoginRouteService {

    private final VerifyPasswordLoginIdentityService credentials;
    private final ResolveTrustedDeviceRouteService devices;
    private final PasswordOperationStore operations;

    public PasswordLoginRouteService(VerifyPasswordLoginIdentityService credentials,
                                     ResolveTrustedDeviceRouteService devices,
                                     PasswordOperationStore operations) {
        this.credentials = Objects.requireNonNull(credentials, "credentials");
        this.devices = Objects.requireNonNull(devices, "devices");
        this.operations = Objects.requireNonNull(operations, "operations");
    }

    public PasswordLoginRouteResult route(PasswordLoginCommand command) {
        PasswordLoginIdentityResult credential = credentials.verifyIdentity(command);
        if (credential instanceof PasswordLoginIdentityResult.MfaUnavailable) {
            return new PasswordLoginRouteResult.MfaUnavailable();
        }
        if (credential instanceof PasswordLoginIdentityResult.Rejected) {
            return new PasswordLoginRouteResult.Rejected();
        }
        if (credential instanceof PasswordLoginIdentityResult.Conflict) {
            return new PasswordLoginRouteResult.Conflict();
        }
        if (credential instanceof PasswordLoginIdentityResult.AuthorityClosed) {
            return new PasswordLoginRouteResult.AuthorityClosed();
        }
        if (!(credential instanceof PasswordLoginIdentityResult.Verified verified)) {
            return new PasswordLoginRouteResult.Processing();
        }

        TrustedDeviceRoute route = devices.resolve(command.operation().operationId(),
                verified.subjectId(), command.operation().appId(), command.now());
        if (route == TrustedDeviceRoute.LAST_TRUSTED) {
            return new PasswordLoginRouteResult.LastTrusted(verified.subjectId());
        }
        if (route == TrustedDeviceRoute.REJECTED) {
            return new PasswordLoginRouteResult.Rejected();
        }
        PasswordCredentialRecordResult saved = operations.recordMfaUnavailable(
                command.operation().operationId(), route);
        return saved == PasswordCredentialRecordResult.NOT_RECORDABLE
                ? new PasswordLoginRouteResult.Processing()
                : new PasswordLoginRouteResult.MfaUnavailable();
    }
}
