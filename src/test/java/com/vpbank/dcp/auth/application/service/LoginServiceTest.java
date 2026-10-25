package com.vpbank.dcp.auth.application.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.vpbank.dcp.auth.application.port.in.LoginCommand;
import com.vpbank.dcp.auth.application.port.in.LoginResult;
import com.vpbank.dcp.auth.application.port.out.CredentialVerifierPort;
import com.vpbank.dcp.auth.application.port.out.CredentialVerifierPort.VerificationResult;
import com.vpbank.dcp.auth.application.port.out.CustomerAuthentication;
import com.vpbank.dcp.auth.application.port.out.CustomerAuthenticationRepository;
import com.vpbank.dcp.auth.application.port.out.OpaqueTokenGenerator;
import com.vpbank.dcp.auth.application.port.out.PartnerUnavailableException;
import com.vpbank.dcp.auth.application.port.out.TokenEnvelopeSealer;
import com.vpbank.dcp.auth.domain.model.Channel;
import com.vpbank.dcp.auth.domain.model.CustomerId;
import com.vpbank.dcp.auth.domain.model.DeviceId;
import com.vpbank.dcp.auth.domain.model.OpaqueToken;
import com.vpbank.dcp.auth.domain.model.Password;
import com.vpbank.dcp.auth.domain.model.SessionId;
import com.vpbank.dcp.auth.domain.model.SessionPolicy;
import com.vpbank.dcp.auth.domain.model.SessionStatus;
import com.vpbank.dcp.auth.domain.model.UserName;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class LoginServiceTest {
    private static final Instant NOW = Instant.parse("2026-10-25T10:00:00Z");
    private static final UserName ALICE = new UserName("alice");
    private static final OpaqueToken TOKEN = new OpaqueToken("k1.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    private static final String KENC = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"..\",\"y\":\"..\"}";

    private final CustomerAuthenticationRepository identities = mock(CustomerAuthenticationRepository.class);
    private final CredentialVerifierPort credentials = mock(CredentialVerifierPort.class);
    private final InMemorySessionStore sessions = new InMemorySessionStore();
    private final TokenEnvelopeSealer sealer = mock(TokenEnvelopeSealer.class);
    private final OpaqueTokenGenerator tokens = mock(OpaqueTokenGenerator.class);
    private final LoginService service = new LoginService(identities, credentials, sessions, sealer, tokens,
            SessionId::random, new SessionPolicy(Duration.ofMinutes(15), Duration.ofMinutes(20), Duration.ofSeconds(30)),
            Clock.fixed(NOW, ZoneOffset.UTC));

    @BeforeEach
    void happyPath() {
        when(identities.findByUserName(ALICE)).thenReturn(Optional.of(identity("ACTIVE")));
        when(credentials.verify(eq(ALICE), any())).thenReturn(new VerificationResult.Verified("iss", "sub-1"));
        when(tokens.next()).thenReturn(TOKEN);
        when(sealer.seal(eq(KENC), eq(TOKEN), any())).thenReturn("jwe.compact");
    }

    @Test
    void issuesASessionAndSealsTheTokenNeverReturningItInClear() {
        Password password = new Password("Secret123".toCharArray());
        LoginResult result = service.login(command(password));

        assertThat(result).isInstanceOf(LoginResult.Authenticated.class);
        LoginResult.Authenticated ok = (LoginResult.Authenticated) result;
        assertThat(ok.tokenEnvelope()).isEqualTo("jwe.compact");
        assertThat(ok.customerId()).isEqualTo(new CustomerId("90359"));
        assertThat(ok.status()).isEqualTo(SessionStatus.ACTIVE);
        assertThat(ok.idleExpiresAt()).isEqualTo(NOW.plus(Duration.ofMinutes(15)));
        assertThat(ok.absoluteExpiresAt()).isEqualTo(NOW.plus(Duration.ofMinutes(20)));
        assertThat(ok.toString()).doesNotContain("jwe");
        assertThat(sessions.findByToken(TOKEN)).isPresent();
        assertThat(sessions.only().deviceId()).isEqualTo(new DeviceId("dev-1"));
        assertThat(sessions.only().channel()).isEqualTo(Channel.MOBILE);
        assertThat(password.value()).containsOnly('\0');
    }

    @Test
    void unknownUserAndWrongPasswordGiveTheSameAnswerAndBothAskKeycloak() {
        when(identities.findByUserName(ALICE)).thenReturn(Optional.empty());
        assertThat(service.login(command())).isInstanceOf(LoginResult.InvalidCredentials.class);
        verify(credentials).verify(eq(ALICE), any());

        when(identities.findByUserName(ALICE)).thenReturn(Optional.of(identity("ACTIVE")));
        when(credentials.verify(eq(ALICE), any())).thenReturn(new VerificationResult.Rejected());
        assertThat(service.login(command())).isInstanceOf(LoginResult.InvalidCredentials.class);
        assertThat(sessions.rows).isEmpty();
        verifyNoInteractions(sealer);
    }

    @Test
    void aKeycloakUserThatIsNotTheStoredIdentityIsInvalid() {
        when(credentials.verify(eq(ALICE), any())).thenReturn(new VerificationResult.Verified("iss", "someone-else"));
        assertThat(service.login(command())).isInstanceOf(LoginResult.InvalidCredentials.class);
    }

    @Test
    void anInactiveIdentityIsNotReadyEvenWithTheRightPassword() {
        when(identities.findByUserName(ALICE)).thenReturn(Optional.of(identity("SUSPENDED")));
        assertThat(service.login(command())).isInstanceOf(LoginResult.AccountNotReady.class);
        assertThat(sessions.rows).isEmpty();
    }

    @Test
    void partnerOrStoreOutageIsUnavailableAndNothingIsIssued() {
        when(credentials.verify(eq(ALICE), any())).thenThrow(new PartnerUnavailableException("Keycloak"));
        assertThat(service.login(command())).isInstanceOf(LoginResult.Unavailable.class);

        when(credentials.verify(eq(ALICE), any())).thenReturn(new VerificationResult.Verified("iss", "sub-1"));
        sessions.unavailable = true;
        assertThat(service.login(command())).isInstanceOf(LoginResult.Unavailable.class);
    }

    private static LoginCommand command() {
        return command(new Password("Secret123".toCharArray()));
    }

    private static LoginCommand command(Password password) {
        return LoginCommand.builder().userName(ALICE).password(password).channel(Channel.MOBILE)
                .deviceId(new DeviceId("dev-1")).tokenEncryptionKey(KENC).build();
    }

    private static CustomerAuthentication identity(String status) {
        return CustomerAuthentication.builder().customerId(new CustomerId("90359")).userName(ALICE)
                .identityIssuer("iss").identitySubject("sub-1").status(status).build();
    }
}
