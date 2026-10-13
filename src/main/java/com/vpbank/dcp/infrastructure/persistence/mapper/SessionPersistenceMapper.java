package com.vpbank.dcp.infrastructure.persistence.mapper;

import com.vpbank.dcp.core.domain.security.Digest32;
import com.vpbank.dcp.core.domain.security.LookupKeyVersion;
import com.vpbank.dcp.core.domain.session.SessionDeadlines;
import com.vpbank.dcp.core.port.out.session.SessionActivationSnapshot;
import com.vpbank.dcp.core.port.out.session.PreparedSession;
import com.vpbank.dcp.core.port.out.session.SessionDelivery;
import com.vpbank.dcp.core.port.out.session.SessionTokenLookup;
import com.vpbank.dcp.core.port.out.session.SessionCandidate;
import com.vpbank.dcp.infrastructure.persistence.codec.EscrowedSessionDelivery;
import com.vpbank.dcp.infrastructure.persistence.projection.PreparedSessionView;

/** Restores the exact durable candidate using current snapshot and decoded delivery. */
public final class SessionPersistenceMapper {
    private SessionPersistenceMapper() { }

    public static Digest32 toRequestKey(PreparedSessionView view) {
        return Digest32.fromBytes(view.requestKey());
    }

    public static Digest32 toResultDigest(PreparedSessionView view) {
        return Digest32.fromBytes(view.resultDigest());
    }

    public static PreparedSession toPreparedSession(SessionActivationSnapshot snapshot,
            PreparedSessionView view, EscrowedSessionDelivery delivery) {
        var lookup = new SessionTokenLookup(new LookupKeyVersion(view.lookupVersion()),
                Digest32.fromBytes(view.lookupDigest()));
        var candidate = new SessionCandidate(view.intentId(), view.sessionId(), view.generation(),
                lookup, Digest32.fromBytes(view.candidateDigest()));
        var restoredDelivery = new SessionDelivery(delivery.tokenEnvelope(), delivery.receipt(),
                delivery.dpopNonce(), view.deliveryDeadline());
        var deadlines = new SessionDeadlines(view.idleExpiresAt(), view.absoluteExpiresAt());
        return new PreparedSession(snapshot, candidate, restoredDelivery, deadlines);
    }
}
