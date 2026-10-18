package com.vpbank.dcp.core.application.session;

import com.vpbank.dcp.core.domain.device.BindingId;
import com.vpbank.dcp.core.domain.customer.SubjectId;
import com.vpbank.dcp.core.domain.customer.CustomerNumber;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.vpbank.dcp.core.domain.customer.CustomerAuthenticationState;
import com.vpbank.dcp.core.domain.customer.CustomerStatus;
import com.vpbank.dcp.core.port.in.session.LoginConfirmation;
import com.vpbank.dcp.core.port.in.session.SessionLoginEvidence;
import com.vpbank.dcp.core.port.in.session.SessionLoginResult;
import com.vpbank.dcp.core.domain.security.Digest32;
import com.vpbank.dcp.core.port.out.device.LoginDeviceSnapshot;
import com.vpbank.dcp.core.port.out.password.StoredDeviceKey;
import com.vpbank.dcp.core.port.out.session.LoginSessionSecurity;
import com.vpbank.dcp.core.port.out.session.LoginSessionSecurityStore;
import com.vpbank.dcp.core.port.out.session.SessionSecurityVersions;
import com.vpbank.dcp.core.port.out.session.StoredCustomerSecurity;
import com.vpbank.dcp.core.port.out.session.StoredDeviceSecurity;
import com.vpbank.dcp.core.port.out.session.PreparedSession;
import com.vpbank.dcp.core.port.out.session.SessionApplyResult;
import com.vpbank.dcp.core.port.out.session.SessionAuthority;
import com.vpbank.dcp.core.port.out.session.SessionCryptography;
import com.vpbank.dcp.core.port.out.session.SessionKeyBindings;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class IssueLoginSessionServiceTest {
    private final LoginSessionSecurityStore security = mock(LoginSessionSecurityStore.class);
    private final SessionCryptography cryptography = mock(SessionCryptography.class);
    private final SessionAuthority authority = mock(SessionAuthority.class);
    private final IssueLoginSessionService service = new IssueLoginSessionService(
            security, cryptography, authority, Duration.ofSeconds(30));
    private final Instant now = Instant.parse("2026-10-13T00:00:00Z");

    @Test
    void primaryPasswordIssuesActiveWhenGuardsRemainCurrent() {
        Fixture fixture = fixture(true, LoginConfirmation.PRIMARY_PASSWORD);
        PreparedSession prepared = mock(PreparedSession.class);
        when(security.current(fixture.subject, fixture.bindingId, "neo-mobile"))
                .thenReturn(Optional.of(fixture.guard));
        when(authority.currentGeneration()).thenReturn(Optional.of(fixture.generation));
        when(cryptography.prepare(any(), any(), any(), any())).thenReturn(prepared);
        when(authority.apply(prepared)).thenReturn(SessionApplyResult.APPLIED);
        when(authority.deliverable(prepared)).thenReturn(true);

        assertThat(service.issue(UUID.randomUUID(), now, fixture.evidence))
                .isEqualTo(new SessionLoginResult.Active(prepared));
        verify(authority, never()).revoke(prepared);
    }

    @Test
    void nonPrimaryPasswordCannotIssueActive() {
        Fixture fixture = fixture(false, LoginConfirmation.PRIMARY_PASSWORD);
        when(security.current(fixture.subject, fixture.bindingId, "neo-mobile"))
                .thenReturn(Optional.of(fixture.guard));

        assertThat(service.issue(UUID.randomUUID(), now, fixture.evidence))
                .isInstanceOf(SessionLoginResult.Rejected.class);
        verify(authority, never()).apply(any());
    }

    @Test
    void verifiedTotpCanIssueOnOtherTrustedDevice() {
        Fixture fixture = fixture(false, LoginConfirmation.MFA_CONFIRMED);
        PreparedSession prepared = mock(PreparedSession.class);
        when(security.current(fixture.subject, fixture.bindingId, "neo-mobile"))
                .thenReturn(Optional.of(fixture.guard));
        when(authority.currentGeneration()).thenReturn(Optional.of(fixture.generation));
        when(cryptography.prepare(any(), any(), any(), any())).thenReturn(prepared);
        when(authority.apply(prepared)).thenReturn(SessionApplyResult.APPLIED);
        when(authority.deliverable(prepared)).thenReturn(true);

        assertThat(service.issue(UUID.randomUUID(), now, fixture.evidence))
                .isEqualTo(new SessionLoginResult.Active(prepared));
    }

    @Test
    void guardChangeAfterPublicationRevokesCandidate() {
        Fixture fixture = fixture(true, LoginConfirmation.PRIMARY_PASSWORD);
        LoginSessionSecurity revoked = new LoginSessionSecurity(
                new StoredCustomerSecurity(true, 3),
                new StoredDeviceSecurity(false, now.plusSeconds(3600), false),
                new SessionSecurityVersions(0, 0, 2),
                false);
        PreparedSession prepared = mock(PreparedSession.class);
        when(security.current(fixture.subject, fixture.bindingId, "neo-mobile"))
                .thenReturn(Optional.of(fixture.guard), Optional.of(revoked));
        when(authority.currentGeneration()).thenReturn(Optional.of(fixture.generation));
        when(cryptography.prepare(any(), any(), any(), any())).thenReturn(prepared);
        when(authority.apply(prepared)).thenReturn(SessionApplyResult.APPLIED);

        assertThat(service.issue(UUID.randomUUID(), now, fixture.evidence))
                .isInstanceOf(SessionLoginResult.Unavailable.class);
        verify(authority).revoke(prepared);
    }

    @Test
    void redisLossNeverIssuesActive() {
        Fixture fixture = fixture(true, LoginConfirmation.PRIMARY_PASSWORD);
        when(security.current(fixture.subject, fixture.bindingId, "neo-mobile"))
                .thenReturn(Optional.of(fixture.guard));
        when(authority.currentGeneration()).thenReturn(Optional.empty());

        assertThat(service.issue(UUID.randomUUID(), now, fixture.evidence))
                .isInstanceOf(SessionLoginResult.Unavailable.class);
        verify(cryptography, never()).prepare(any(), any(), any(), any());
    }

    private Fixture fixture(boolean primary, LoginConfirmation confirmation) {
        SubjectId subject = new SubjectId(UUID.randomUUID());
        BindingId bindingId = new BindingId(UUID.randomUUID());
        UUID generation = UUID.randomUUID();
        Digest32 digest = Digest32.fromBytes(new byte[32]);
        LoginDeviceSnapshot device = new LoginDeviceSnapshot(bindingId, subject, "neo-mobile", "ANDROID",
                true, primary, true, now.plusSeconds(3600), 1,
                new StoredDeviceKey(new byte[]{1}, digest));
        SessionKeyBindings keys = new SessionKeyBindings(digest,
                "request-jwk", "response-jwk", digest);
        CustomerAuthenticationState customer = new CustomerAuthenticationState(new CustomerNumber("customer-a"),
                CustomerStatus.ELIGIBLE, 3, 0, now);
        SessionLoginEvidence evidence = new SessionLoginEvidence(subject, customer, device, keys,
                generation, confirmation);
        LoginSessionSecurity guard = new LoginSessionSecurity(
                new StoredCustomerSecurity(true, 3),
                new StoredDeviceSecurity(true, now.plusSeconds(3600), primary),
                new SessionSecurityVersions(0, 0, 1),
                false);
        return new Fixture(evidence, guard, subject, bindingId, generation);
    }

    private record Fixture(SessionLoginEvidence evidence, LoginSessionSecurity guard,
                           SubjectId subject, BindingId bindingId, UUID generation) { }
}
