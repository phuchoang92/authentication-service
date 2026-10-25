package com.vpbank.dcp.auth.application.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.vpbank.dcp.auth.application.command.CaptchaSolution;
import com.vpbank.dcp.auth.application.command.LoginCommand;
import com.vpbank.dcp.auth.application.result.LoginResult;
import com.vpbank.dcp.auth.application.port.out.gateway.CredentialVerifierPort;
import com.vpbank.dcp.auth.application.port.out.gateway.CredentialVerifierPort.VerificationResult;
import com.vpbank.dcp.auth.application.port.out.model.CustomerAuthentication;
import com.vpbank.dcp.auth.application.port.out.gateway.OpaqueTokenGenerator;
import com.vpbank.dcp.auth.application.port.out.exception.PartnerUnavailableException;
import com.vpbank.dcp.auth.application.port.out.gateway.TokenEnvelopeSealer;
import com.vpbank.dcp.auth.domain.model.CaptchaAnswer;
import com.vpbank.dcp.auth.domain.model.CaptchaId;
import com.vpbank.dcp.auth.domain.model.Channel;
import com.vpbank.dcp.auth.domain.model.CustomerId;
import com.vpbank.dcp.auth.domain.model.DeviceId;
import com.vpbank.dcp.auth.domain.model.DevicePlatform;
import com.vpbank.dcp.auth.domain.model.DevicePolicy;
import com.vpbank.dcp.auth.domain.model.TrustedDevice;
import com.vpbank.dcp.auth.domain.model.TrustedDeviceId;
import com.vpbank.dcp.auth.domain.model.LockoutPolicy;
import com.vpbank.dcp.auth.domain.model.OpaqueToken;
import com.vpbank.dcp.auth.domain.model.Password;
import com.vpbank.dcp.auth.domain.model.PasswordLockout;
import com.vpbank.dcp.auth.domain.model.PasswordStatus;
import com.vpbank.dcp.auth.domain.model.SessionId;
import com.vpbank.dcp.auth.domain.model.SessionPolicy;
import com.vpbank.dcp.auth.domain.model.SessionStatus;
import com.vpbank.dcp.auth.domain.model.UserName;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class LoginServiceTest {
    private static final Instant NOW = Instant.parse("2026-10-25T10:00:00Z");
    private static final CustomerId CUSTOMER = new CustomerId("90359");
    private static final UserName ALICE = new UserName("alice");
    private static final OpaqueToken TOKEN = new OpaqueToken("k1.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    private static final String KENC = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"..\",\"y\":\"..\"}";

    private final InMemoryCustomerAuthenticationRepository identities = new InMemoryCustomerAuthenticationRepository();
    private final CredentialVerifierPort credentials = mock(CredentialVerifierPort.class);
    private final InMemoryCaptchaStore captchas = new InMemoryCaptchaStore();
    private final InMemorySessionStore sessions = new InMemorySessionStore();
    private final TokenEnvelopeSealer sealer = mock(TokenEnvelopeSealer.class);
    private final OpaqueTokenGenerator tokens = mock(OpaqueTokenGenerator.class);
    private final InMemoryTrustedDeviceRepository devices = new InMemoryTrustedDeviceRepository();
    private final Clock clock = Clock.fixed(NOW, ZoneOffset.UTC);
    private final LoginService service = new LoginService(identities, credentials, captchas, sessions, sealer, tokens,
            SessionId::random, new TrustedDeviceService(devices, DevicePolicy.standard(), TrustedDeviceId::random, clock),
            new SessionPolicy(Duration.ofMinutes(15), Duration.ofMinutes(20), Duration.ofSeconds(30)),
            LockoutPolicy.standard(), DevicePolicy.standard(), clock);

    @BeforeEach
    void happyPath() {
        identities.rows.put(CUSTOMER, identity("ACTIVE", PasswordLockout.none()));
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
        assertThat(ok.customerId()).isEqualTo(CUSTOMER);
        assertThat(ok.status()).isEqualTo(SessionStatus.ACTIVE);
        assertThat(ok.idleExpiresAt()).isEqualTo(NOW.plus(Duration.ofMinutes(15)));
        assertThat(ok.absoluteExpiresAt()).isEqualTo(NOW.plus(Duration.ofMinutes(20)));
        assertThat(ok.toString()).doesNotContain("jwe");
        assertThat(sessions.findByToken(TOKEN)).isPresent();
        assertThat(sessions.only().deviceId()).isEqualTo(new DeviceId("dev-1"));
        assertThat(sessions.only().channel()).isEqualTo(Channel.MOBILE);
        assertThat(password.value()).containsOnly('\0');
        assertThat(identities.only().version()).isZero(); // no lockout write when nothing to reset
        // The first device of the customer was trusted and made primary on the way.
        assertThat(devices.only().deviceId()).isEqualTo(new DeviceId("dev-1"));
        assertThat(devices.findPrimary(CUSTOMER, Channel.MOBILE)).contains(devices.only().id());
    }

    @Test
    void aSecondDeviceGetsARestrictedNeedTrustedDeviceSessionWithATenMinuteTtl() {
        TrustedDevice phone = TrustedDevice.trustedNow(TrustedDeviceId.random(), CUSTOMER, Channel.MOBILE,
                new DeviceId("phone"), DevicePlatform.ANDROID, null, NOW, DevicePolicy.standard());
        devices.rows.put(phone.id(), phone);
        devices.primaries.put(new InMemoryTrustedDeviceRepository.Key(CUSTOMER, Channel.MOBILE), phone.id());

        LoginResult result = service.login(command());

        assertThat(result).isInstanceOf(LoginResult.Authenticated.class);
        LoginResult.Authenticated restricted = (LoginResult.Authenticated) result;
        assertThat(restricted.status()).isEqualTo(SessionStatus.NEED_TRUSTED_DEVICE);
        assertThat(restricted.idleExpiresAt()).isEqualTo(NOW.plus(Duration.ofMinutes(10)));
        assertThat(restricted.absoluteExpiresAt()).isEqualTo(NOW.plus(Duration.ofMinutes(10)));
        assertThat(sessions.only().status()).isEqualTo(SessionStatus.NEED_TRUSTED_DEVICE);
        assertThat(devices.rows).hasSize(1); // the tablet is not registered by the direct path
    }

    @Test
    void aWebLoginNeedsNoDeviceAndIsAlwaysFull() {
        LoginCommand web = LoginCommand.builder().userName(ALICE).password(new Password("Secret123".toCharArray()))
                .channel(Channel.WEB).tokenEncryptionKey(KENC).build();
        assertThat(((LoginResult.Authenticated) service.login(web)).status()).isEqualTo(SessionStatus.ACTIVE);
        assertThat(devices.rows).isEmpty();
        assertThatThrownBy(() -> LoginCommand.builder().userName(ALICE).password(new Password("x".toCharArray()))
                .channel(Channel.MOBILE).tokenEncryptionKey(KENC).build()).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void unknownUserAndWrongPasswordGiveTheSameAnswerAndBothAskKeycloak() {
        identities.rows.clear();
        assertThat(service.login(command())).isInstanceOf(LoginResult.InvalidCredentials.class);
        verify(credentials).verify(eq(ALICE), any());

        identities.rows.put(CUSTOMER, identity("ACTIVE", PasswordLockout.none()));
        when(credentials.verify(eq(ALICE), any())).thenReturn(new VerificationResult.Rejected());
        assertThat(service.login(command())).isInstanceOf(LoginResult.InvalidCredentials.class);
        assertThat(sessions.rows).isEmpty();
        verifyNoInteractions(sealer);
    }

    @Test
    void eachFailureIsCountedAndTheThirdLocksWithoutAskingKeycloakAfterwards() {
        when(credentials.verify(eq(ALICE), any())).thenReturn(new VerificationResult.Rejected());

        assertThat(service.login(command())).isInstanceOf(LoginResult.InvalidCredentials.class);
        assertThat(service.login(command())).isInstanceOf(LoginResult.InvalidCredentials.class);
        assertThat(identities.only().lockout().failedCount()).isEqualTo(2);
        assertThat(service.login(withCaptcha(command()))).isInstanceOf(LoginResult.AccountLocked.class);
        assertThat(identities.only().lockout().status()).isEqualTo(PasswordStatus.LOCKED);
        assertThat(identities.only().lockout().lockedUntil()).isEqualTo(NOW.plus(Duration.ofMinutes(15)));
        verify(credentials, org.mockito.Mockito.times(3)).verify(eq(ALICE), any());

        when(credentials.verify(eq(ALICE), any())).thenReturn(new VerificationResult.Verified("iss", "sub-1"));
        assertThat(service.login(withCaptcha(command()))).isInstanceOf(LoginResult.AccountLocked.class);
        verify(credentials, org.mockito.Mockito.times(3)).verify(eq(ALICE), any()); // short-circuited
        assertThat(identities.only().lockout().failedCount()).isEqualTo(2 + 1);
    }

    @Test
    void aPermanentlyLockedIdentityStaysLockedAndASuccessResetsTheCount() {
        identities.rows.put(CUSTOMER, identity("ACTIVE", new PasswordLockout(PasswordStatus.PERMANENTLY_LOCKED, 5, null)));
        assertThat(service.login(command())).isInstanceOf(LoginResult.AccountLocked.class);
        verify(credentials, never()).verify(any(), any());

        identities.rows.put(CUSTOMER, identity("ACTIVE", new PasswordLockout(PasswordStatus.ACTIVE, 2, null)));
        assertThat(service.login(withCaptcha(command()))).isInstanceOf(LoginResult.Authenticated.class);
        assertThat(identities.only().lockout()).isEqualTo(PasswordLockout.none());
    }

    @Test
    void anExpiredTemporaryLockLetsTheCustomerTryAndTheNextFailureEscalates() {
        identities.rows.put(CUSTOMER, identity("ACTIVE",
                new PasswordLockout(PasswordStatus.LOCKED, 3, NOW.minusSeconds(1))));
        when(credentials.verify(eq(ALICE), any())).thenReturn(new VerificationResult.Rejected());

        assertThat(service.login(withCaptcha(command()))).isInstanceOf(LoginResult.AccountLocked.class);
        assertThat(identities.only().lockout().failedCount()).isEqualTo(4);
        assertThat(identities.only().lockout().lockedUntil()).isEqualTo(NOW.plus(Duration.ofHours(24)));
    }

    @Test
    void aConcurrentFailureIsNotLostTheRowIsReReadAndEscalatedFromTheLatestCount() {
        when(credentials.verify(eq(ALICE), any())).thenReturn(new VerificationResult.Rejected());
        identities.rows.put(CUSTOMER, identity("ACTIVE", new PasswordLockout(PasswordStatus.ACTIVE, 1, null)));
        identities.concurrentFailures = 1; // another attempt lands first: count becomes 2

        assertThat(service.login(command())).isInstanceOf(LoginResult.AccountLocked.class);
        assertThat(identities.only().lockout().failedCount()).isEqualTo(3);
    }

    @Test
    void afterTwoFailuresALoginNeedsACaptchaBoundToThisCustomerAndAMissingOrWrongOneCostsNoAttempt() {
        identities.rows.put(CUSTOMER, identity("ACTIVE", new PasswordLockout(PasswordStatus.ACTIVE, 2, null)));

        assertThat(service.login(command())).isInstanceOf(LoginResult.CaptchaRequired.class);
        verify(credentials, never()).verify(any(), any());
        assertThat(identities.only().lockout().failedCount()).isEqualTo(2);

        CaptchaId id = CaptchaId.random();
        captchas.save(id, CUSTOMER, new CaptchaAnswer("AB3CD"), NOW.plusSeconds(300));
        assertThat(service.login(withCaptcha(command(), id, "WRONG"))).isInstanceOf(LoginResult.CaptchaRequired.class);
        assertThat(captchas.challenges).isEmpty(); // a wrong answer burns the challenge
        verify(credentials, never()).verify(any(), any());

        CaptchaId other = CaptchaId.random();
        captchas.save(other, new CustomerId("77777"), new CaptchaAnswer("AB3CD"), NOW.plusSeconds(300));
        assertThat(service.login(withCaptcha(command(), other, "AB3CD"))).isInstanceOf(LoginResult.CaptchaRequired.class);

        assertThat(service.login(withCaptcha(command()))).isInstanceOf(LoginResult.Authenticated.class);
        assertThat(identities.only().lockout()).isEqualTo(PasswordLockout.none());
    }

    @Test
    void aKeycloakUserThatIsNotTheStoredIdentityIsInvalidAndCounted() {
        when(credentials.verify(eq(ALICE), any())).thenReturn(new VerificationResult.Verified("iss", "someone-else"));
        assertThat(service.login(command())).isInstanceOf(LoginResult.InvalidCredentials.class);
        assertThat(identities.only().lockout().failedCount()).isEqualTo(1);
    }

    @Test
    void anInactiveIdentityIsNotReadyEvenWithTheRightPassword() {
        identities.rows.put(CUSTOMER, identity("SUSPENDED", PasswordLockout.none()));
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
        sessions.unavailable = false;
        identities.unavailable = true;
        assertThat(service.login(command())).isInstanceOf(LoginResult.Unavailable.class);
    }

    private static LoginCommand command() {
        return command(new Password("Secret123".toCharArray()));
    }

    /** A freshly issued, correct CAPTCHA for the customer. */
    private LoginCommand withCaptcha(LoginCommand command) {
        CaptchaId id = CaptchaId.random();
        captchas.save(id, CUSTOMER, new CaptchaAnswer("AB3CD"), NOW.plusSeconds(300));
        return withCaptcha(command, id, "ab3cd");
    }

    private static LoginCommand withCaptcha(LoginCommand command, CaptchaId id, String answer) {
        return LoginCommand.builder().userName(command.userName()).password(command.password()).channel(command.channel())
                .deviceId(command.deviceId()).platform(command.platform()).tokenEncryptionKey(command.tokenEncryptionKey())
                .captcha(new CaptchaSolution(id, new CaptchaAnswer(answer))).build();
    }

    private static LoginCommand command(Password password) {
        return LoginCommand.builder().userName(ALICE).password(password).channel(Channel.MOBILE)
                .deviceId(new DeviceId("dev-1")).platform(DevicePlatform.ANDROID).tokenEncryptionKey(KENC).build();
    }

    private static CustomerAuthentication identity(String status, PasswordLockout lockout) {
        return CustomerAuthentication.builder().customerId(CUSTOMER).userName(ALICE)
                .identityIssuer("iss").identitySubject("sub-1").status(status).lockout(lockout).version(0).build();
    }
}
