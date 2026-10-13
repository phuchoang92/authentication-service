package com.vpbank.dcp.infrastructure.persistence.mapper;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.vpbank.dcp.core.domain.security.Digest32;
import com.vpbank.dcp.core.domain.security.LookupKeyVersion;
import com.vpbank.dcp.core.domain.session.InvalidSessionStateException;
import com.vpbank.dcp.core.domain.session.SessionDeadlines;
import com.vpbank.dcp.core.domain.session.SessionAssurance;
import com.vpbank.dcp.core.port.out.session.SessionActivationFacts;
import com.vpbank.dcp.core.port.out.session.PreparedSession;
import com.vpbank.dcp.infrastructure.persistence.codec.EscrowedSessionDelivery;
import com.vpbank.dcp.infrastructure.persistence.projection.PasswordSessionFactsView;
import com.vpbank.dcp.infrastructure.persistence.projection.PreparedSessionView;
import java.time.Instant;
import java.util.Arrays;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class PasswordSessionPersistenceMapperTest {
    private final UUID operationId = UUID.randomUUID();
    private final UUID journeyId = UUID.randomUUID();
    private final UUID subjectId = UUID.randomUUID();
    private final UUID bindingId = UUID.randomUUID();
    private final UUID intentId = UUID.randomUUID();
    private final UUID sessionId = UUID.randomUUID();
    private final UUID generation = UUID.randomUUID();
    private final Instant checkedAt = Instant.parse("2026-10-12T14:00:00.123456Z");
    private final Instant validUntil = checkedAt.plusSeconds(237);
    private final EscrowedSessionDelivery delivery = new EscrowedSessionDelivery(
            "exact-envelope", "exact-receipt", "exact-nonce");

    @Test
    void restoresAllFrozenFactsWithTheExplicitFreshnessDeadline() {
        var facts = PasswordSessionPersistenceMapper.toFacts(factsView(), validUntil);
        assertThat(facts).isEqualTo(new SessionActivationFacts(operationId, journeyId, subjectId,
                "mobile", bindingId, Digest32.fromBytes(bytes(1)), "request-jwk", "response-jwk",
                Digest32.fromBytes(bytes(2)), 11, 22, 33, 44, validUntil, new SessionAssurance(SessionAssurance.DevicePossession.MFA_KEY_POSSESSION,
                SessionAssurance.PlatformEvidence.NONE, SessionAssurance.BiometricEnforcement.NOT_APPLICABLE), true));
        // Mapping performs no expiry decision even when the supplied deadline is in the past.
        assertThat(PasswordSessionPersistenceMapper.toFacts(factsView(), Instant.EPOCH)
                .customerStatusValidUntil()).isEqualTo(Instant.EPOCH);
    }

    @ParameterizedTest
    @ValueSource(strings = {"UNKNOWN", "CLIENT_ENFORCED", "HARDWARE_KEY"})
    void unsupportedPlatformClaimsCannotBecomePasswordAssurance(String evidence) {
        var old = factsView();
        var view = new PasswordSessionFactsView(old.operationId(), old.journeyId(), old.subjectId(),
                old.appId(), old.bindingId(), old.requestKey(), old.requestPublicJwk(), old.responsePublicJwk(),
                old.deviceKey(), old.customerSecurityVersion(), old.credentialSecurityVersion(),
                old.deviceSecurityVersion(), old.customerStatusVersion(), old.customerCheckedAt(), evidence,
                old.biometricLoginEnabled());
        assertThatThrownBy(() -> PasswordSessionPersistenceMapper.toFacts(view, validUntil))
                .isInstanceOf(InvalidSessionStateException.class);
    }

    @Test
    void restoresExactCandidateAndPreviouslyDecodedDelivery() {
        var facts = PasswordSessionPersistenceMapper.toFacts(factsView(), validUntil);
        var view = preparedView("lookup_k2", bytes(3), checkedAt.plusSeconds(900), checkedAt.plusSeconds(3600));
        var restored = SessionPersistenceMapper.toPreparedSession(facts, view, delivery);
        assertThat(restored).isEqualTo(new PreparedSession(facts, intentId, sessionId, generation,
                new LookupKeyVersion("lookup_k2"), Digest32.fromBytes(bytes(3)), Digest32.fromBytes(bytes(4)),
                "exact-envelope", "exact-receipt", "exact-nonce",
                new SessionDeadlines(checkedAt.plusSeconds(900), checkedAt.plusSeconds(3600)),
                checkedAt.plusSeconds(120)));
        assertThat(SessionPersistenceMapper.toRequestKey(view)).isEqualTo(facts.requestKey());
        assertThat(SessionPersistenceMapper.toResultDigest(view)).isEqualTo(Digest32.fromBytes(bytes(5)));
    }

    @Test
    void invalidStoredDigestAndLookupVersionRemainErrors() {
        var facts = PasswordSessionPersistenceMapper.toFacts(factsView(), validUntil);
        assertThatThrownBy(() -> SessionPersistenceMapper.toPreparedSession(facts,
                preparedView("lookup_k2", new byte[31], checkedAt, checkedAt), delivery))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> SessionPersistenceMapper.toPreparedSession(facts,
                preparedView("bad/version", bytes(3), checkedAt, checkedAt), delivery))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void reversedSessionDeadlinesCannotBeRestored() {
        var facts = PasswordSessionPersistenceMapper.toFacts(factsView(), validUntil);
        assertThatThrownBy(() -> SessionPersistenceMapper.toPreparedSession(facts,
                preparedView("lookup_k2", bytes(3), checkedAt.plusSeconds(2), checkedAt.plusSeconds(1)), delivery))
                .isInstanceOf(InvalidSessionStateException.class);
    }

    private PasswordSessionFactsView factsView() {
        return new PasswordSessionFactsView(operationId, journeyId, subjectId, "mobile", bindingId,
                bytes(1), "request-jwk", "response-jwk", bytes(2), 11, 22, 33, 44,
                checkedAt, "NONE", true);
    }

    private PreparedSessionView preparedView(String keyVersion, byte[] lookupDigest,
            Instant idleExpiry, Instant absoluteExpiry) {
        return new PreparedSessionView(intentId, sessionId, generation, keyVersion,
                lookupDigest, bytes(4), idleExpiry, absoluteExpiry, checkedAt.plusSeconds(120),
                new byte[]{9, 8, 7}, bytes(5), 11, 22, 33, bytes(1), bindingId, subjectId);
    }

    private byte[] bytes(int value) {
        byte[] bytes = new byte[32];
        Arrays.fill(bytes, (byte) value);
        return bytes;
    }
}
