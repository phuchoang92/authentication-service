package com.vpbank.dcp.core.application.session;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.vpbank.dcp.core.domain.security.Digest32;
import com.vpbank.dcp.core.domain.security.LookupKeyVersion;
import com.vpbank.dcp.core.domain.session.SessionAssurance;
import com.vpbank.dcp.core.domain.session.SessionDeadlines;
import com.vpbank.dcp.core.port.in.session.ActivateSessionCommand;
import com.vpbank.dcp.core.port.in.session.SessionActivationResult;
import com.vpbank.dcp.core.port.out.session.PrepareSessionResult;
import com.vpbank.dcp.core.port.out.session.PreparedSession;
import com.vpbank.dcp.core.port.out.session.SessionActivationSnapshot;
import com.vpbank.dcp.core.port.out.session.CustomerStatusFreshness;
import com.vpbank.dcp.core.port.out.session.SessionSecurityVersions;
import com.vpbank.dcp.core.port.out.session.SessionKeyBindings;
import com.vpbank.dcp.core.port.out.session.SessionActivationContext;
import com.vpbank.dcp.core.port.out.session.SessionApplyResult;
import com.vpbank.dcp.core.port.out.session.SessionAuthority;
import com.vpbank.dcp.core.port.out.session.SessionCryptography;
import com.vpbank.dcp.core.port.out.session.SessionRepository;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

class ActivateSessionServiceTest {
    private static final Instant NOW = Instant.parse("2026-10-13T00:00:00Z");
    private final SessionRepository repository = mock(SessionRepository.class);
    private final SessionCryptography cryptography = mock(SessionCryptography.class);
    private final SessionAuthority authority = mock(SessionAuthority.class);
    private final ActivateSessionService service = new ActivateSessionService(repository,
            cryptography, authority, Clock.fixed(NOW, ZoneOffset.UTC));
    private final ActivateSessionCommand command = new ActivateSessionCommand(UUID.randomUUID(), UUID.randomUUID());
    private final UUID generation = UUID.randomUUID();
    private final SessionActivationSnapshot snapshot = snapshot(command.subjectId());
    private final PreparedSession candidate = candidate(snapshot, NOW.plusSeconds(120));

    @Test
    void preparesDurablyBeforePublishingAndReauthorizesBeforeDelivery() {
        when(repository.currentSnapshot(command.operationId(), command.subjectId())).thenReturn(Optional.of(snapshot));
        when(authority.currentGeneration()).thenReturn(Optional.of(generation));
        when(cryptography.prepare(snapshot, generation, SessionDeadlines.createdAt(NOW), NOW.plusSeconds(120)))
                .thenReturn(candidate);
        when(repository.prepare(candidate)).thenReturn(new PrepareSessionResult.Prepared(candidate));
        deliverable(candidate, SessionApplyResult.APPLIED);

        assertThat(service.activate(command)).isEqualTo(new SessionActivationResult.Active(candidate));

        var order = inOrder(repository, cryptography, authority);
        order.verify(repository).prepared(command.operationId());
        order.verify(repository).currentSnapshot(command.operationId(), command.subjectId());
        order.verify(authority).currentGeneration();
        order.verify(cryptography).prepare(snapshot, generation, SessionDeadlines.createdAt(NOW), NOW.plusSeconds(120));
        order.verify(repository).prepare(candidate);
        order.verify(authority).apply(candidate);
        order.verify(repository).markApplied(command.operationId(), candidate.intentId());
        order.verify(authority).deliverable(candidate);
    }

    @ParameterizedTest
    @EnumSource(value = SessionApplyResult.class, names = {"APPLIED", "ALREADY_APPLIED"})
    void recoveryUsesExactStoredCandidateWithoutIssuingAnotherToken(SessionApplyResult applied) {
        when(repository.prepared(command.operationId())).thenReturn(Optional.of(candidate));
        deliverable(candidate, applied);

        assertThat(service.activate(command)).isEqualTo(new SessionActivationResult.Active(candidate));

        verifyNoInteractions(cryptography);
        verify(repository, never()).currentSnapshot(any(), any());
        verify(repository, never()).prepare(any());
        verify(authority, never()).currentGeneration();
    }

    @Test
    void losingPreparationPublishesTheOriginalWinnerAndDiscardsItsOwnCandidate() {
        PreparedSession winner = candidate(snapshot, NOW.plusSeconds(100));
        when(repository.currentSnapshot(command.operationId(), command.subjectId())).thenReturn(Optional.of(snapshot));
        when(authority.currentGeneration()).thenReturn(Optional.of(generation));
        when(cryptography.prepare(any(), any(), any(), any())).thenReturn(candidate);
        when(repository.prepare(candidate)).thenReturn(new PrepareSessionResult.Existing(winner));
        deliverable(winner, SessionApplyResult.ALREADY_APPLIED);

        assertThat(service.activate(command)).isEqualTo(new SessionActivationResult.Active(winner));

        verify(authority, never()).apply(candidate);
    }

    @Test
    void unconfirmedOperationCannotCreateASession() {
        assertThat(service.activate(command)).isInstanceOf(SessionActivationResult.Rejected.class);
        verifyNoInteractions(cryptography, authority);
    }

    @Test
    void wrongCurrentOwnerCannotCreateASession() {
        when(repository.currentSnapshot(command.operationId(), command.subjectId()))
                .thenReturn(Optional.of(snapshot(UUID.randomUUID())));
        assertThat(service.activate(command)).isInstanceOf(SessionActivationResult.Rejected.class);
        verifyNoInteractions(cryptography, authority);
    }

    @Test
    void wrongStoredOwnerCannotPublishOrDeliver() {
        when(repository.prepared(command.operationId()))
                .thenReturn(Optional.of(candidate(snapshot(UUID.randomUUID()), NOW.plusSeconds(120))));
        assertThat(service.activate(command)).isInstanceOf(SessionActivationResult.Rejected.class);
        verifyNoInteractions(cryptography, authority);
        verify(repository, never()).markApplied(any(), any());
    }

    @Test
    void deliveryExpiresAtTheExactDeadline() {
        when(repository.prepared(command.operationId())).thenReturn(Optional.of(candidate(snapshot, NOW)));
        assertThat(service.activate(command)).isInstanceOf(SessionActivationResult.Rejected.class);
        verifyNoInteractions(cryptography, authority);
    }

    @Test
    void missingGenerationRemainsProcessingWithoutPreparingAToken() {
        when(repository.currentSnapshot(command.operationId(), command.subjectId())).thenReturn(Optional.of(snapshot));
        assertThat(service.activate(command)).isInstanceOf(SessionActivationResult.Processing.class);
        verifyNoInteractions(cryptography);
        verify(repository, never()).prepare(any());
        verify(authority, never()).apply(any());
    }

    @Test
    void rejectedDurablePreparationCannotPublish() {
        when(repository.currentSnapshot(command.operationId(), command.subjectId())).thenReturn(Optional.of(snapshot));
        when(authority.currentGeneration()).thenReturn(Optional.of(generation));
        when(cryptography.prepare(any(), any(), any(), any())).thenReturn(candidate);
        when(repository.prepare(candidate)).thenReturn(new PrepareSessionResult.Rejected());
        assertThat(service.activate(command)).isInstanceOf(SessionActivationResult.Rejected.class);
        verify(authority, never()).apply(any());
    }

    @ParameterizedTest
    @EnumSource(value = SessionApplyResult.class, names = {"DENIED", "AUTHORITY_CLOSED"})
    void refusedPublicationCannotCompleteOrDeliver(SessionApplyResult applied) {
        when(repository.prepared(command.operationId())).thenReturn(Optional.of(candidate));
        when(authority.apply(candidate)).thenReturn(applied);
        assertThat(service.activate(command)).isInstanceOf(SessionActivationResult.Processing.class);
        verify(repository, never()).markApplied(any(), any());
        verify(authority, never()).deliverable(any());
    }

    @Test
    void incompleteSqlCompletionCannotDeliver() {
        when(repository.prepared(command.operationId())).thenReturn(Optional.of(candidate));
        when(authority.apply(candidate)).thenReturn(SessionApplyResult.APPLIED);
        assertThat(service.activate(command)).isInstanceOf(SessionActivationResult.Processing.class);
        verify(authority, never()).deliverable(any());
    }

    @Test
    void lostLiveAuthorityAfterSqlCompletionCannotDeliver() {
        when(repository.prepared(command.operationId())).thenReturn(Optional.of(candidate));
        when(authority.apply(candidate)).thenReturn(SessionApplyResult.APPLIED);
        when(repository.markApplied(command.operationId(), candidate.intentId())).thenReturn(true);
        assertThat(service.activate(command)).isInstanceOf(SessionActivationResult.Processing.class);
        verify(authority).deliverable(candidate);
    }

    private void deliverable(PreparedSession session, SessionApplyResult applied) {
        when(authority.apply(session)).thenReturn(applied);
        when(repository.markApplied(command.operationId(), session.intentId())).thenReturn(true);
        when(authority.deliverable(session)).thenReturn(true);
    }

    private SessionActivationSnapshot snapshot(UUID subjectId) {
        return new SessionActivationSnapshot(
                new SessionActivationContext(command.operationId(), UUID.randomUUID(), subjectId,
                        "mobile", UUID.randomUUID()),
                new SessionKeyBindings(digest(1), "request-jwk", "response-jwk", digest(2)),
                new SessionSecurityVersions(1, 2, 3),
                new CustomerStatusFreshness(4, NOW.plusSeconds(300)),
                new SessionAssurance(SessionAssurance.DevicePossession.MFA_KEY_POSSESSION,
                        SessionAssurance.PlatformEvidence.NONE, SessionAssurance.BiometricEnforcement.NOT_APPLICABLE),
                false);
    }

    private PreparedSession candidate(SessionActivationSnapshot snapshot, Instant deadline) {
        return new PreparedSession(snapshot, UUID.randomUUID(), UUID.randomUUID(), generation,
                new LookupKeyVersion("k1"), digest(3), digest(4), "encrypted-only",
                "signed-receipt", UUID.randomUUID().toString(), SessionDeadlines.createdAt(NOW), deadline);
    }

    private Digest32 digest(int marker) {
        byte[] bytes = new byte[32];
        bytes[0] = (byte) marker;
        return Digest32.fromBytes(bytes);
    }
}
