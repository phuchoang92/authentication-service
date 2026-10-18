package com.vpbank.dcp.core.application.password;

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
import com.vpbank.dcp.core.domain.security.Digest32;
import com.vpbank.dcp.core.domain.security.LookupKeyVersion;
import com.vpbank.dcp.core.domain.security.RequestKeyThumbprint;
import com.vpbank.dcp.core.port.in.password.PasswordLoginCommand;
import com.vpbank.dcp.core.port.out.device.LoginDeviceSnapshot;
import com.vpbank.dcp.core.port.out.credential.PasswordVerification;
import com.vpbank.dcp.core.port.out.password.PasswordOperationContext;
import com.vpbank.dcp.core.port.out.password.PasswordProofIds;
import com.vpbank.dcp.core.port.out.password.PasswordWireProofs;
import com.vpbank.dcp.core.port.out.password.StoredDeviceKey;
import com.vpbank.dcp.core.port.out.password.VerifiedPasswordProofs;
import com.vpbank.dcp.core.port.out.pending.PendingTokenCryptography;
import com.vpbank.dcp.core.port.out.pending.PendingMfaLogin;
import com.vpbank.dcp.core.port.out.pending.PendingMfaLoginStore;
import com.vpbank.dcp.core.port.out.pending.PreparedPendingToken;
import com.vpbank.dcp.core.port.out.security.VerifiedDpopProof;
import com.vpbank.dcp.core.port.out.session.SessionTokenLookup;
import com.vpbank.dcp.core.port.out.totp.DeviceTotpAvailability;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class StartTotpLoginServiceTest {
    private final DeviceTotpAvailability credentials = mock(DeviceTotpAvailability.class);
    private final PendingTokenCryptography cryptography = mock(PendingTokenCryptography.class);
    private final PendingMfaLoginStore pending = mock(PendingMfaLoginStore.class);
    private final StartTotpLoginService service = new StartTotpLoginService(
            credentials, cryptography, pending, new SecureRandom(), Duration.ofMinutes(5));
    private final Instant now = Instant.parse("2026-10-13T00:00:00Z");

    @Test
    void unconfirmedCredentialCannotCreatePendingLogin() {
        Fixture fixture = fixture();
        assertThat(service.start(fixture.command, fixture.assessment))
                .isInstanceOf(StartTotpLoginResult.NeedsRecovery.class);
        verify(cryptography, never()).issue(any());
    }

    @Test
    void confirmedCredentialGetsRestrictedSingleChallenge() {
        Fixture fixture = fixture();
        when(credentials.hasActiveCredential(fixture.assessment.device().bindingId())).thenReturn(true);
        var lookup = new SessionTokenLookup(new LookupKeyVersion("test"), Digest32.fromBytes(new byte[32]));
        var token = new PreparedPendingToken(lookup, "encrypted-envelope", "signed-receipt");
        when(cryptography.issue(any())).thenReturn(token);
        when(pending.create(any(), any())).thenReturn(true);

        StartTotpLoginResult result = service.start(fixture.command, fixture.assessment);
        assertThat(result).isInstanceOf(StartTotpLoginResult.Ready.class);
        StartTotpLoginResult.Ready ready = (StartTotpLoginResult.Ready) result;
        assertThat(ready.token()).isSameAs(token);
        assertThat(ready.authenticationId()).hasSize(32);
        assertThat(ready.challengeId()).hasSize(32);
        assertThat(ready.expiresAt()).isEqualTo(now.plusSeconds(300));
        verify(pending).create(any(), any(PendingMfaLogin.class));
    }

    private Fixture fixture() {
        Digest32 digest = Digest32.fromBytes(new byte[32]);
        SubjectId subject = new SubjectId(UUID.randomUUID());
        VerifiedDpopProof dpop = new VerifiedDpopProof(new RequestKeyThumbprint(digest),
                digest, now, "request-jwk");
        PasswordLoginCommand command = new PasswordLoginCommand(new PasswordOperationContext(
                UUID.randomUUID(), "neo-mobile", "ANDROID", "installation-1234567890", "alice",
                "QkJCQkJCQkJCQkJCQkJCQg"), new PasswordVerification("alice", "secret"),
                new PasswordWireProofs(dpop, "request-proof", "device-proof", "response-jwk"),
                now, now.plusSeconds(8), now.plusSeconds(900));
        var device = new LoginDeviceSnapshot(new BindingId(UUID.randomUUID()), subject, "neo-mobile", "ANDROID",
                true, true, false, now.plusSeconds(3600), 1,
                new StoredDeviceKey(new byte[]{1}, digest));
        var proofs = new VerifiedPasswordProofs(new RequestKeyThumbprint(digest), digest, digest,
                new PasswordProofIds(digest, digest, digest), "request-jwk", "response-jwk");
        var customer = new CustomerAuthenticationState(new CustomerNumber("customer-a"), CustomerStatus.ELIGIBLE, 1, 0, now);
        return new Fixture(command, new AuthenticatedLogin(subject, customer,
                device, new AdmittedProof(proofs, UUID.randomUUID())));
    }

    private record Fixture(PasswordLoginCommand command, AuthenticatedLogin assessment) { }
}
