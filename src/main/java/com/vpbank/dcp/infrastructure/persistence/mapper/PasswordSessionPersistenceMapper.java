package com.vpbank.dcp.infrastructure.persistence.mapper;

import com.vpbank.dcp.core.domain.security.Digest32;
import com.vpbank.dcp.core.domain.session.SessionAssurance;
import com.vpbank.dcp.core.domain.session.InvalidSessionStateException;
import com.vpbank.dcp.core.port.out.session.SessionActivationFacts;
import com.vpbank.dcp.infrastructure.persistence.projection.PasswordSessionFactsView;
import java.time.Instant;

/** Restores confirmed password-source facts and their assurance using supplied freshness. */
public final class PasswordSessionPersistenceMapper {
    private PasswordSessionPersistenceMapper() { }

    public static SessionActivationFacts toFacts(PasswordSessionFactsView view, Instant customerStatusValidUntil) {
        return new SessionActivationFacts(view.operationId(), view.journeyId(), view.subjectId(),
                view.appId(), view.bindingId(), Digest32.fromBytes(view.requestKey()),
                view.requestPublicJwk(), view.responsePublicJwk(), Digest32.fromBytes(view.deviceKey()),
                view.customerSecurityVersion(), view.credentialSecurityVersion(), view.deviceSecurityVersion(),
                view.customerStatusVersion(), customerStatusValidUntil, passwordAssurance(view.platformAssurance()),
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
