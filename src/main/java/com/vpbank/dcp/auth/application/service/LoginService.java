package com.vpbank.dcp.auth.application.service;

import com.vpbank.dcp.auth.application.port.in.LoginCommand;
import com.vpbank.dcp.auth.application.port.in.LoginResult;
import com.vpbank.dcp.auth.application.port.in.LoginUseCase;
import com.vpbank.dcp.auth.application.port.out.CaptchaStore;
import com.vpbank.dcp.auth.application.port.out.CredentialVerifierPort;
import com.vpbank.dcp.auth.application.port.out.CredentialVerifierPort.VerificationResult;
import com.vpbank.dcp.auth.application.port.out.CustomerAuthentication;
import com.vpbank.dcp.auth.application.port.out.CustomerAuthenticationRepository;
import com.vpbank.dcp.auth.application.port.out.OpaqueTokenGenerator;
import com.vpbank.dcp.auth.application.port.out.PartnerUnavailableException;
import com.vpbank.dcp.auth.application.port.out.RepositoryUnavailableException;
import com.vpbank.dcp.auth.application.port.out.SessionStore;
import com.vpbank.dcp.auth.application.port.out.TokenEnvelopeSealer;
import com.vpbank.dcp.auth.application.service.TrustedDeviceService.DeviceRouting;
import com.vpbank.dcp.auth.domain.model.DevicePolicy;
import com.vpbank.dcp.auth.domain.model.LockoutPolicy;
import com.vpbank.dcp.auth.domain.model.OpaqueToken;
import com.vpbank.dcp.auth.domain.model.PasswordLockout;
import com.vpbank.dcp.auth.domain.model.Session;
import com.vpbank.dcp.auth.domain.model.SessionId;
import com.vpbank.dcp.auth.domain.model.SessionPolicy;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;

import java.time.Clock;
import java.time.Instant;
import java.util.Optional;
import java.util.function.Supplier;

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
    @NonNull private final CustomerAuthenticationRepository identities;
    @NonNull private final CredentialVerifierPort credentials;
    @NonNull private final CaptchaStore captchas;
    @NonNull private final SessionStore sessions;
    @NonNull private final TokenEnvelopeSealer sealer;
    @NonNull private final OpaqueTokenGenerator tokens;
    @NonNull private final Supplier<SessionId> sessionIds;
    @NonNull private final TrustedDeviceService trustedDevices;
    @NonNull private final SessionPolicy policy;
    @NonNull private final LockoutPolicy lockoutPolicy;
    @NonNull private final DevicePolicy devicePolicy;
    @NonNull private final Clock clock;

    /** A challenge is consumed on first use whether right or wrong, so a guess costs a new CAPTCHA. */
    private boolean captchaSolved(LoginCommand command, com.vpbank.dcp.auth.domain.model.CustomerId customerId) {
        return command.captcha() != null
                && captchas.consume(command.captcha().captchaId(), customerId, command.captcha().answer());
    }

    /**
     * One more failure on this identity. A stale write means another failure landed first; the
     * row is re-read once so the escalation is applied to the latest count, then the attempt is
     * answered. If the write still loses, the other writer's lock (if any) stands.
     */
    private LoginResult recordFailure(CustomerAuthentication identity) {
        Instant now = clock.instant();
        Optional<CustomerAuthentication> saved = identities.saveLockoutIfCurrent(identity,
                identity.lockout().afterFailure(now, lockoutPolicy));
        if (saved.isEmpty()) {
            saved = identities.findByUserName(identity.userName())
                    .flatMap(latest -> identities.saveLockoutIfCurrent(latest, latest.lockout().afterFailure(now, lockoutPolicy)));
        }
        PasswordLockout lockout = saved.map(CustomerAuthentication::lockout).orElse(identity.lockout());
        return lockout.isLocked(now) ? new LoginResult.AccountLocked() : new LoginResult.InvalidCredentials();
    }

    @Override
    public LoginResult login(LoginCommand command) {
        try {
            Optional<CustomerAuthentication> identity = identities.findByUserName(command.userName());
            if (identity.isPresent() && identity.get().lockout().isLocked(clock.instant())) {
                return new LoginResult.AccountLocked();
            }
            if (identity.isPresent() && identity.get().lockout().captchaRequired(lockoutPolicy)
                    && !captchaSolved(command, identity.get().customerId())) {
                return new LoginResult.CaptchaRequired();
            }
            VerificationResult verified = credentials.verify(command.userName(), command.password());
            if (identity.isEmpty() || !(verified instanceof VerificationResult.Verified(var issuer, var subject))
                    || !identity.get().isSameIdentity(issuer, subject)) {
                return identity.map(this::recordFailure).orElseGet(LoginResult.InvalidCredentials::new);
            }
            if (!identity.get().isActive()) {
                return new LoginResult.AccountNotReady();
            }
            if (identity.get().lockout().failedCount() > 0) {
                identities.saveLockoutIfCurrent(identity.get(), identity.get().lockout().reset());
            }
            SessionId sessionId = sessionIds.get();
            DeviceRouting routing = trustedDevices.routeAfterPassword(identity.get().customerId(), command.channel(),
                    command.deviceId(), command.platform(), command.devicePublicKey(), sessionId.toString());
            Session session = switch (routing) {
                case DeviceRouting.FullSession() -> Session.start(sessionId, identity.get().customerId(),
                        command.deviceId(), command.channel(), clock.instant(), policy);
                case DeviceRouting.NeedTrust() -> Session.startRestricted(sessionId, identity.get().customerId(),
                        command.deviceId(), command.channel(), clock.instant(), devicePolicy);
            };
            OpaqueToken token = tokens.next();
            String envelope = sealer.seal(command.tokenEncryptionKey(), token, session);
            sessions.create(session, token);
            return new LoginResult.Authenticated(envelope, session.customerId(), session.status(),
                    session.idleExpiresAt(), session.absoluteExpiresAt());
        } catch (RepositoryUnavailableException | PartnerUnavailableException failure) {
            return new LoginResult.Unavailable();
        } finally {
            command.password().clear();
        }
    }
}
