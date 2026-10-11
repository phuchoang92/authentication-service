package com.vpbank.dcp.core.application.password;

import com.vpbank.dcp.core.domain.device.TrustedDeviceRoute;
import com.vpbank.dcp.core.port.out.password.PasswordCredentialRecordResult;
import com.vpbank.dcp.core.port.out.password.PasswordOperationStore;
import java.util.Objects;

/** Freezes unsupported MFA routes without creating a challenge or a banking token. */
public final class PasswordLoginRouteService {

    private final PasswordCredentialCheckService credentials;
    private final PasswordDeviceRouteService devices;
    private final PasswordOperationStore operations;

    public PasswordLoginRouteService(PasswordCredentialCheckService credentials,
                                     PasswordDeviceRouteService devices,
                                     PasswordOperationStore operations) {
        this.credentials = Objects.requireNonNull(credentials, "credentials");
        this.devices = Objects.requireNonNull(devices, "devices");
        this.operations = Objects.requireNonNull(operations, "operations");
    }

    public PasswordLoginRouteResult route(PasswordAdmissionCommand command) {
        PasswordCredentialCheckResult credential = credentials.check(command);
        if (credential instanceof PasswordCredentialCheckResult.MfaUnavailable) {
            return new PasswordLoginRouteResult.MfaUnavailable();
        }
        if (credential instanceof PasswordCredentialCheckResult.Rejected) {
            return new PasswordLoginRouteResult.Rejected();
        }
        if (credential instanceof PasswordCredentialCheckResult.Conflict) {
            return new PasswordLoginRouteResult.Conflict();
        }
        if (credential instanceof PasswordCredentialCheckResult.AuthorityClosed) {
            return new PasswordLoginRouteResult.AuthorityClosed();
        }
        if (!(credential instanceof PasswordCredentialCheckResult.Verified verified)) {
            return new PasswordLoginRouteResult.Processing();
        }

        TrustedDeviceRoute route = devices.route(command.operation().operationId(),
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
