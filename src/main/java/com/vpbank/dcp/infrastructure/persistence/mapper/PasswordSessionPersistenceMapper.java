package com.vpbank.dcp.infrastructure.persistence.mapper;

import com.vpbank.dcp.core.domain.security.Digest32;
import com.vpbank.dcp.core.domain.security.LookupKeyVersion;
import com.vpbank.dcp.core.domain.session.SessionDeadlines;
import com.vpbank.dcp.core.port.out.session.PasswordSessionFacts;
import com.vpbank.dcp.core.port.out.session.PreparedPasswordSession;
import com.vpbank.dcp.infrastructure.persistence.codec.EscrowedPasswordDelivery;
import com.vpbank.dcp.infrastructure.persistence.projection.PasswordSessionFactsView;
import com.vpbank.dcp.infrastructure.persistence.projection.PreparedPasswordSessionView;
import java.time.Instant;

/** Restores session values using freshness and decoded delivery supplied by the adapter. */
public final class PasswordSessionPersistenceMapper {
    private PasswordSessionPersistenceMapper() { }

    public static PasswordSessionFacts toFacts(PasswordSessionFactsView view, Instant customerStatusValidUntil) {
        return new PasswordSessionFacts(view.operationId(), view.journeyId(), view.subjectId(),
                view.appId(), view.bindingId(), Digest32.fromBytes(view.requestKey()),
                view.requestPublicJwk(), view.responsePublicJwk(), Digest32.fromBytes(view.deviceKey()),
                view.customerSecurityVersion(), view.credentialSecurityVersion(), view.deviceSecurityVersion(),
                view.customerStatusVersion(), customerStatusValidUntil, view.platformAssurance(),
                view.biometricLoginEnabled());
    }

    public static Digest32 toRequestKey(PreparedPasswordSessionView view) {
        return Digest32.fromBytes(view.requestKey());
    }

    public static Digest32 toResultDigest(PreparedPasswordSessionView view) {
        return Digest32.fromBytes(view.resultDigest());
    }

    public static PreparedPasswordSession toPreparedSession(PasswordSessionFacts facts,
            PreparedPasswordSessionView view, EscrowedPasswordDelivery delivery) {
        return new PreparedPasswordSession(facts, view.intentId(), view.sessionId(), view.generation(),
                new LookupKeyVersion(view.lookupVersion()), Digest32.fromBytes(view.lookupDigest()),
                Digest32.fromBytes(view.candidateDigest()), delivery.tokenEnvelope(), delivery.receipt(),
                delivery.dpopNonce(), new SessionDeadlines(view.idleExpiresAt(), view.absoluteExpiresAt()),
                view.deliveryDeadline());
    }
}
