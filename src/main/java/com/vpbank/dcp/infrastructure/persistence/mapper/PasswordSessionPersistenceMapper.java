package com.vpbank.dcp.infrastructure.persistence.mapper;

import com.vpbank.dcp.core.domain.security.Digest32;
import com.vpbank.dcp.core.domain.session.SessionAssurance;
import com.vpbank.dcp.core.domain.session.InvalidSessionStateException;
import com.vpbank.dcp.core.port.out.session.SessionActivationSnapshot;
import com.vpbank.dcp.core.port.out.session.CustomerStatusFreshness;
import com.vpbank.dcp.core.port.out.session.SessionSecurityVersions;
import com.vpbank.dcp.core.port.out.session.SessionKeyBindings;
import com.vpbank.dcp.core.port.out.session.SessionActivationContext;
import com.vpbank.dcp.infrastructure.persistence.projection.PasswordSessionSnapshotView;
import java.time.Instant;

/** Restores a confirmed password-source snapshot with its assurance and supplied freshness. */
public final class PasswordSessionPersistenceMapper {
    private PasswordSessionPersistenceMapper() { }

    public static SessionActivationSnapshot toSnapshot(PasswordSessionSnapshotView view, Instant customerStatusValidUntil) {
        return new SessionActivationSnapshot(
                new SessionActivationContext(view.operationId(), view.journeyId(), view.subjectId(),
                        view.appId(), view.bindingId()),
                new SessionKeyBindings(Digest32.fromBytes(view.requestKey()), view.requestPublicJwk(),
                        view.responsePublicJwk(), Digest32.fromBytes(view.deviceKey())),
                new SessionSecurityVersions(view.customerSecurityVersion(),
                        view.credentialSecurityVersion(), view.deviceSecurityVersion()),
                new CustomerStatusFreshness(view.customerStatusVersion(), customerStatusValidUntil),
                passwordAssurance(view.platformAssurance()),
                view.biometricLoginEnabled());
    }

    private static SessionAssurance passwordAssurance(String platformEvidence) {
        return new SessionAssurance(SessionAssurance.DevicePossession.MFA_KEY_POSSESSION,
                switch (platformEvidence) {
                    case "NONE" -> SessionAssurance.PlatformEvidence.NONE;
                    default -> throw new InvalidSessionStateException();
                }, SessionAssurance.BiometricEnforcement.NOT_APPLICABLE);
    }
}
