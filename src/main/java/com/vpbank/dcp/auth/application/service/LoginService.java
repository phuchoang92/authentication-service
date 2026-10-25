package com.vpbank.dcp.auth.application.service;

import com.vpbank.dcp.auth.application.command.CaptchaSolution;
import com.vpbank.dcp.auth.application.command.LoginCommand;
import com.vpbank.dcp.auth.application.port.in.LoginUseCase;
import com.vpbank.dcp.auth.application.port.out.exception.PartnerUnavailableException;
import com.vpbank.dcp.auth.application.port.out.exception.RepositoryUnavailableException;
import com.vpbank.dcp.auth.application.port.out.gateway.CredentialVerifierPort;
import com.vpbank.dcp.auth.application.port.out.gateway.CredentialVerifierPort.VerificationResult;
import com.vpbank.dcp.auth.application.port.out.gateway.OpaqueTokenGenerator;
import com.vpbank.dcp.auth.application.port.out.gateway.TokenEnvelopeSealer;
import com.vpbank.dcp.auth.application.port.out.model.CustomerAuthentication;
import com.vpbank.dcp.auth.application.port.out.repository.CaptchaStore;
import com.vpbank.dcp.auth.application.port.out.repository.CustomerAuthenticationRepository;
import com.vpbank.dcp.auth.application.port.out.repository.SessionStore;
import com.vpbank.dcp.auth.application.result.LoginResult;
import com.vpbank.dcp.auth.application.service.TrustedDeviceService.DeviceRouting;
import com.vpbank.dcp.auth.domain.model.CustomerId;
import com.vpbank.dcp.auth.domain.model.DevicePolicy;
import com.vpbank.dcp.auth.domain.model.LockoutPolicy;
import com.vpbank.dcp.auth.domain.model.OpaqueToken;
import com.vpbank.dcp.auth.domain.model.PasswordLockout;
import com.vpbank.dcp.auth.domain.model.Session;
import com.vpbank.dcp.auth.domain.model.SessionId;
import com.vpbank.dcp.auth.domain.model.SessionPolicy;
import java.time.Clock;
import java.time.Instant;
import java.util.Optional;
import java.util.function.Supplier;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;

/**
 * Password login: identity row → lockout check → Keycloak password check → same issuer/subject →
 * new ACTIVE session in the store → token sealed to the app's key.
 *
 * <p>Unknown user and wrong password give the same answer, so nothing reveals whether an account
 * exists; Keycloak is still asked for an unknown user so the two paths take similar time. A locked
 * identity answers from the database alone; once the CAPTCHA threshold is reached, an attempt
 * without a valid CAPTCHA bound to this customer is refused before Keycloak and does not count as
 * a password failure (slice 3 policy). Every failure on an existing identity
 * is counted with compare-and-set; only a success resets the count. The password is wiped as soon
 * as the provider has answered. After the password, {@link TrustedDeviceService} decides whether this
 * device gets a full ACTIVE session or a restricted NEED_TRUSTED_DEVICE one (DD 20 §2).
 */
@RequiredArgsConstructor
public final class LoginService implements LoginUseCase {
    @NonNull private final CustomerAuthenticationRepository customerAuthenticationRepository;
    @NonNull private final CredentialVerifierPort credentialVerifierPort;
    @NonNull private final CaptchaStore captchaStore;
    @NonNull private final SessionStore sessionStore;
    @NonNull private final TokenEnvelopeSealer tokenEnvelopeSealer;
    @NonNull private final OpaqueTokenGenerator opaqueTokenGenerator;
    @NonNull private final Supplier<SessionId> sessionIdGenerator;
    @NonNull private final TrustedDeviceService trustedDeviceService;
    @NonNull private final SessionPolicy sessionPolicy;
    @NonNull private final LockoutPolicy lockoutPolicy;
    @NonNull private final DevicePolicy devicePolicy;
    @NonNull private final Clock clock;

    @Override
    public LoginResult login(LoginCommand command) {
        try {
            Optional<CustomerAuthentication> foundIdentity =
                    customerAuthenticationRepository.findByUserName(command.userName());

            if (foundIdentity.isPresent()) {
                CustomerAuthentication identity = foundIdentity.get();
                if (identity.lockout().isLocked(clock.instant())) {
                    return new LoginResult.AccountLocked();
                }
                boolean captchaRequired = identity.lockout().captchaRequired(lockoutPolicy);
                if (captchaRequired && !captchaSolved(command, identity.customerId())) {
                    return new LoginResult.CaptchaRequired();
                }
            }

            // Keycloak is asked even for an unknown user, so both answers take similar time.
            VerificationResult verificationResult =
                    credentialVerifierPort.verify(command.userName(), command.password());
            if (foundIdentity.isEmpty()) {
                return new LoginResult.InvalidCredentials();
            }
            CustomerAuthentication identity = foundIdentity.get();

            boolean passwordAccepted =
                    verificationResult instanceof VerificationResult.Verified(var issuer, var subject)
                            && identity.isSameIdentity(issuer, subject);
            if (!passwordAccepted) {
                return recordFailure(identity);
            }

            if (!identity.isActive()) {
                return new LoginResult.AccountNotReady();
            }

            if (identity.lockout().failedCount() > 0) {
                PasswordLockout resetLockout = identity.lockout().reset();
                customerAuthenticationRepository.saveLockoutIfCurrent(identity, resetLockout);
            }

            SessionId sessionId = sessionIdGenerator.get();
            String correlationId = sessionId.toString();
            DeviceRouting deviceRouting = trustedDeviceService.routeAfterPassword(
                    identity.customerId(),
                    command.channel(),
                    command.deviceId(),
                    command.platform(),
                    command.devicePublicKey(),
                    correlationId);

            Instant now = clock.instant();
            Session session = switch (deviceRouting) {
                case DeviceRouting.FullSession() -> Session.start(
                        sessionId,
                        identity.customerId(),
                        command.deviceId(),
                        command.channel(),
                        now,
                        sessionPolicy);
                case DeviceRouting.NeedTrust() -> Session.startRestricted(
                        sessionId,
                        identity.customerId(),
                        command.deviceId(),
                        command.channel(),
                        now,
                        devicePolicy);
            };

            OpaqueToken token = opaqueTokenGenerator.next();
            String tokenEnvelope = tokenEnvelopeSealer.seal(command.tokenEncryptionKey(), token, session);
            sessionStore.create(session, token);

            return new LoginResult.Authenticated(
                    tokenEnvelope,
                    session.customerId(),
                    session.status(),
                    session.idleExpiresAt(),
                    session.absoluteExpiresAt());
        } catch (RepositoryUnavailableException | PartnerUnavailableException failure) {
            return new LoginResult.Unavailable();
        } finally {
            command.password().clear();
        }
    }

    /** A challenge is consumed on first use whether right or wrong, so a guess costs a new CAPTCHA. */
    private boolean captchaSolved(LoginCommand command, CustomerId customerId) {
        CaptchaSolution captchaSolution = command.captcha();
        if (captchaSolution == null) {
            return false;
        }
        return captchaStore.consume(captchaSolution.captchaId(), customerId, captchaSolution.answer());
    }

    /**
     * One more failure on this identity. A stale write means another failure landed first; the
     * row is re-read once so the escalation is applied to the latest count, then the attempt is
     * answered. If the write still loses, the other writer's lock (if any) stands.
     */
    private LoginResult recordFailure(CustomerAuthentication identity) {
        Instant now = clock.instant();

        PasswordLockout escalatedLockout = identity.lockout().afterFailure(now, lockoutPolicy);
        Optional<CustomerAuthentication> savedIdentity =
                customerAuthenticationRepository.saveLockoutIfCurrent(identity, escalatedLockout);

        if (savedIdentity.isEmpty()) {
            Optional<CustomerAuthentication> latestIdentity =
                    customerAuthenticationRepository.findByUserName(identity.userName());
            savedIdentity = latestIdentity.flatMap(latest -> {
                PasswordLockout latestEscalatedLockout = latest.lockout().afterFailure(now, lockoutPolicy);
                return customerAuthenticationRepository.saveLockoutIfCurrent(latest, latestEscalatedLockout);
            });
        }

        PasswordLockout effectiveLockout = savedIdentity
                .map(CustomerAuthentication::lockout)
                .orElse(identity.lockout());
        if (effectiveLockout.isLocked(now)) {
            return new LoginResult.AccountLocked();
        }
        return new LoginResult.InvalidCredentials();
    }
}
