package com.vpbank.dcp.infrastructure.adapter.out.persistence.repository.session;

import com.vpbank.dcp.core.domain.security.Digest32;
import com.vpbank.dcp.core.domain.security.LookupKeyVersion;
import com.vpbank.dcp.core.domain.session.SessionDeadlines;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/** Stored intent and protected delivery bytes, before current-fact validation. */
public record PreparedPasswordSessionView(UUID intentId, UUID sessionId, UUID generation,
        LookupKeyVersion lookupVersion, Digest32 lookupDigest, Digest32 candidateDigest,
        SessionDeadlines deadlines, Instant deliveryDeadline, byte[] protectedResult,
        Digest32 resultDigest, long customerSecurityVersion, long credentialSecurityVersion,
        long deviceSecurityVersion, Digest32 requestKey, UUID bindingId, UUID subjectId) {
    public PreparedPasswordSessionView {
        protectedResult = protectedResult == null ? null : protectedResult.clone();
        Objects.requireNonNull(resultDigest);
    }

    @Override
    public byte[] protectedResult() { return protectedResult == null ? null : protectedResult.clone(); }

    @Override
    public boolean equals(Object other) {
        return other instanceof PreparedPasswordSessionView view
                && Objects.equals(intentId, view.intentId) && Objects.equals(sessionId, view.sessionId)
                && Objects.equals(generation, view.generation)
                && Objects.equals(lookupVersion, view.lookupVersion)
                && Objects.equals(lookupDigest, view.lookupDigest)
                && Objects.equals(candidateDigest, view.candidateDigest)
                && Objects.equals(deadlines, view.deadlines)
                && Objects.equals(deliveryDeadline, view.deliveryDeadline)
                && java.util.Arrays.equals(protectedResult, view.protectedResult)
                && Objects.equals(resultDigest, view.resultDigest)
                && customerSecurityVersion == view.customerSecurityVersion
                && credentialSecurityVersion == view.credentialSecurityVersion
                && deviceSecurityVersion == view.deviceSecurityVersion
                && Objects.equals(requestKey, view.requestKey)
                && Objects.equals(bindingId, view.bindingId) && Objects.equals(subjectId, view.subjectId);
    }

    @Override
    public int hashCode() {
        return 31 * Objects.hash(intentId, sessionId, generation, lookupVersion, lookupDigest,
                candidateDigest, deadlines, deliveryDeadline, resultDigest, customerSecurityVersion,
                credentialSecurityVersion, deviceSecurityVersion, requestKey, bindingId, subjectId)
                + java.util.Arrays.hashCode(protectedResult);
    }

    @Override
    public String toString() { return "PreparedPasswordSessionView[redacted]"; }
}
