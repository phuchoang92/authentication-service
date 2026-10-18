package com.vpbank.dcp.core.session;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.vpbank.dcp.core.domain.security.Digest32;
import com.vpbank.dcp.core.domain.security.LookupKeyVersion;
import com.vpbank.dcp.core.domain.security.RequestKeyThumbprint;
import com.vpbank.dcp.core.domain.session.SessionDeadlines;
import com.vpbank.dcp.core.port.out.session.SessionTokenLookup;
import com.vpbank.dcp.core.session.ExtendSessionResult.Extended;
import com.vpbank.dcp.core.session.ExtendSessionResult.NotExtended;
import com.vpbank.dcp.core.session.ExtendSessionResult.Reason;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class ExtendSessionServiceTest {
    private static final Instant CREATED = Instant.parse("2026-10-18T03:00:00Z");
    private static final Instant NOW = CREATED.plusSeconds(120);
    private static final UUID GENERATION = UUID.randomUUID();

    private final SessionActivityStore store = mock(SessionActivityStore.class);
    private final ExtendSessionService service = new ExtendSessionService(store,
            Clock.fixed(NOW, ZoneOffset.UTC), Set.of("accounts.read"),
            Duration.ofSeconds(30), Duration.ofSeconds(2));
    private final SessionTokenLookup lookup =
            new SessionTokenLookup(new LookupKeyVersion("k1"), digest(1));
    private final RequestKeyThumbprint requestKey = new RequestKeyThumbprint(digest(2));

    @Test
    void slidesIdleFromAdmissionTime() {
        storeHas(live(SessionDeadlines.createdAt(CREATED), 4));
        when(store.slideIdle(any(), anyLong(), any())).thenReturn(true);

        var result = service.extend(command(NOW.minusSeconds(1)));

        Instant expectedIdle = NOW.minusSeconds(1).plus(SessionDeadlines.IDLE_LIMIT);
        assertThat(result).isEqualTo(new Extended(
                new SessionDeadlines(expectedIdle, CREATED.plus(SessionDeadlines.ABSOLUTE_LIMIT))));
        verify(store).slideIdle(lookup, 4, expectedIdle);
    }

    @Test
    void slideStopsAtAbsoluteDeadline() {
        var nearEnd = new SessionDeadlines(NOW.plusSeconds(60), NOW.plusSeconds(90));
        storeHas(live(nearEnd, 0));
        when(store.slideIdle(any(), anyLong(), any())).thenReturn(true);

        assertThat(service.extend(command(NOW)))
                .isEqualTo(new Extended(new SessionDeadlines(NOW.plusSeconds(90), NOW.plusSeconds(90))));
    }

    @Test
    void routeOutsideAllowlistIsRejectedWithoutReadingValkey() {
        var command = new ExtendSessionCommand(lookup, requestKey, "health.read", UUID.randomUUID(), NOW);

        assertThat(service.extend(command)).isEqualTo(new NotExtended(Reason.INVALID_REQUEST));
        verifyNoInteractions(store);
    }

    @Test
    void admissionTimeMustBeInsideTheWindow() {
        assertThat(service.extend(command(NOW.minusSeconds(31))))
                .isEqualTo(new NotExtended(Reason.INVALID_REQUEST));
        assertThat(service.extend(command(NOW.plusSeconds(3))))
                .isEqualTo(new NotExtended(Reason.INVALID_REQUEST));
        verifyNoInteractions(store);
    }

    @Test
    void admissionTimeAtTheWindowEdgesIsAccepted() {
        storeHas(live(SessionDeadlines.createdAt(CREATED), 0));
        when(store.slideIdle(any(), anyLong(), any())).thenReturn(true);

        assertThat(service.extend(command(NOW.minusSeconds(30)))).isInstanceOf(Extended.class);
        assertThat(service.extend(command(NOW.plusSeconds(2)))).isInstanceOf(Extended.class);
    }

    @Test
    void missingSessionIsGone() {
        when(store.find(lookup)).thenReturn(Optional.empty());

        assertThat(service.extend(command(NOW))).isEqualTo(new NotExtended(Reason.GONE));
    }

    @Test
    void idleAlreadyPassedIsGoneAndNotRevived() {
        storeHas(live(new SessionDeadlines(NOW, NOW.plusSeconds(300)), 0));

        assertThat(service.extend(command(NOW))).isEqualTo(new NotExtended(Reason.GONE));
        verify(store, never()).slideIdle(any(), anyLong(), any());
    }

    @Test
    void staleCustomerStatusIsGone() {
        storeHas(new LiveSession(requestKey, GENERATION, SessionDeadlines.createdAt(CREATED), NOW, 0));

        assertThat(service.extend(command(NOW))).isEqualTo(new NotExtended(Reason.GONE));
    }

    @Test
    void differentRequestKeyIsConflict() {
        storeHas(new LiveSession(new RequestKeyThumbprint(digest(9)), GENERATION,
                SessionDeadlines.createdAt(CREATED), NOW.plusSeconds(600), 0));

        assertThat(service.extend(command(NOW))).isEqualTo(new NotExtended(Reason.CONFLICT));
        verify(store, never()).slideIdle(any(), anyLong(), any());
    }

    @Test
    void sessionFromAnotherGenerationIsConflict() {
        storeHas(live(SessionDeadlines.createdAt(CREATED), 0));
        when(store.currentGeneration()).thenReturn(Optional.of(UUID.randomUUID()));

        assertThat(service.extend(command(NOW))).isEqualTo(new NotExtended(Reason.CONFLICT));
    }

    @Test
    void unknownGenerationIsUnavailable() {
        storeHas(live(SessionDeadlines.createdAt(CREATED), 0));
        when(store.currentGeneration()).thenReturn(Optional.empty());

        assertThat(service.extend(command(NOW))).isEqualTo(new NotExtended(Reason.UNAVAILABLE));
    }

    @Test
    void retryOfAnAlreadyAppliedAdmissionDoesNotWrite() {
        Instant admittedAt = NOW.minusSeconds(1);
        storeHas(live(SessionDeadlines.createdAt(CREATED).slideFor(admittedAt), 5));

        assertThat(service.extend(command(admittedAt))).isInstanceOf(Extended.class);
        verify(store, never()).slideIdle(any(), anyLong(), any());
    }

    @Test
    void lostRaceReReadsAndUsesTheNewVersion() {
        var deadlines = SessionDeadlines.createdAt(CREATED);
        when(store.currentGeneration()).thenReturn(Optional.of(GENERATION));
        when(store.find(lookup)).thenReturn(Optional.of(live(deadlines, 1)), Optional.of(live(deadlines, 2)));
        when(store.slideIdle(any(), anyLong(), any())).thenReturn(false, true);

        assertThat(service.extend(command(NOW))).isInstanceOf(Extended.class);
        verify(store).slideIdle(lookup, 1, NOW.plus(SessionDeadlines.IDLE_LIMIT));
        verify(store).slideIdle(lookup, 2, NOW.plus(SessionDeadlines.IDLE_LIMIT));
    }

    @Test
    void sessionDeletedDuringRaceIsGone() {
        when(store.currentGeneration()).thenReturn(Optional.of(GENERATION));
        when(store.find(lookup)).thenReturn(
                Optional.of(live(SessionDeadlines.createdAt(CREATED), 1)), Optional.empty());
        when(store.slideIdle(any(), anyLong(), any())).thenReturn(false);

        assertThat(service.extend(command(NOW))).isEqualTo(new NotExtended(Reason.GONE));
    }

    @Test
    void racesLostEveryTimeEndInConflict() {
        storeHas(live(SessionDeadlines.createdAt(CREATED), 0));
        when(store.slideIdle(any(), anyLong(), any())).thenReturn(false);

        assertThat(service.extend(command(NOW))).isEqualTo(new NotExtended(Reason.CONFLICT));
        verify(store, times(ExtendSessionService.MAX_ATTEMPTS)).slideIdle(any(), anyLong(), any());
    }

    @Test
    void valkeyFailureIsUnavailable() {
        storeHas(live(SessionDeadlines.createdAt(CREATED), 0));
        when(store.slideIdle(any(), anyLong(), any()))
                .thenThrow(new SessionActivityUnavailableException(new RuntimeException()));

        assertThat(service.extend(command(NOW))).isEqualTo(new NotExtended(Reason.UNAVAILABLE));
    }

    private void storeHas(LiveSession live) {
        when(store.find(lookup)).thenReturn(Optional.of(live));
        when(store.currentGeneration()).thenReturn(Optional.of(GENERATION));
    }

    private LiveSession live(SessionDeadlines deadlines, long version) {
        return new LiveSession(requestKey, GENERATION, deadlines,
                CREATED.plus(SessionDeadlines.ABSOLUTE_LIMIT), version);
    }

    private ExtendSessionCommand command(Instant admittedAt) {
        return new ExtendSessionCommand(lookup, requestKey, "accounts.read", UUID.randomUUID(), admittedAt);
    }

    private static Digest32 digest(int fill) {
        byte[] bytes = new byte[32];
        Arrays.fill(bytes, (byte) fill);
        return Digest32.fromBytes(bytes);
    }
}
