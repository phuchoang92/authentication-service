package com.vpbank.dcp.auth.application.service;

import com.vpbank.dcp.auth.application.command.CaptchaSolution;
import com.vpbank.dcp.auth.application.command.LoginCommand;
import com.vpbank.dcp.auth.application.port.in.LoginUseCase;
import com.vpbank.dcp.auth.application.port.out.exception.PartnerUnavailableException;
import com.vpbank.dcp.auth.application.port.out.exception.RepositoryUnavailableException;
import com.vpbank.dcp.auth.application.port.out.gateway.CredentialVerifierPort.VerificationResult;
import com.vpbank.dcp.auth.application.port.out.gateway.CredentialVerifierPort;
import com.vpbank.dcp.auth.application.port.out.gateway.DeviceProofVerifier;
import com.vpbank.dcp.auth.application.port.out.model.CustomerAuthentication;
import com.vpbank.dcp.auth.application.port.out.model.DeviceProofBindings;
import com.vpbank.dcp.auth.application.port.out.model.SecurityAuditEvent;
import com.vpbank.dcp.auth.application.port.out.repository.CaptchaStore;
import com.vpbank.dcp.auth.application.port.out.repository.CustomerAuthenticationRepository;
import com.vpbank.dcp.auth.application.port.out.repository.LoginProofReplayStore;
import com.vpbank.dcp.auth.application.port.out.repository.SecurityAuditStore;
import com.vpbank.dcp.auth.application.result.LoginResult;
import com.vpbank.dcp.auth.application.service.SessionService.IssuedSession;
import com.vpbank.dcp.auth.application.service.TrustedDeviceService.DevicePossession;
import com.vpbank.dcp.auth.application.service.TrustedDeviceService.DeviceRouting;
import com.vpbank.dcp.auth.domain.enums.SecurityEventReason;
import com.vpbank.dcp.auth.domain.enums.SecurityEventType;
import com.vpbank.dcp.auth.domain.model.CustomerId;
import com.vpbank.dcp.auth.domain.model.DeviceProof;
import com.vpbank.dcp.auth.domain.model.LockoutPolicy;
import com.vpbank.dcp.auth.domain.model.PasswordLockout;
import com.vpbank.dcp.auth.domain.model.Session;
import com.vpbank.dcp.auth.domain.model.SessionId;
import java.time.Clock;
import java.time.Instant;
import java.util.Optional;
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
 *
 * <p>Slice 13: a login never trusts a device. With the device proof enforced, a trusted primary device
 * gets a full session only when the proof it sent verifies under the key its row holds, is bound to this
 * login and carries a nonce used for the first time; otherwise it gets the restricted session like any
 * other device and must run the trust flow. A failed proof is never an error: the password was right.
 *
 * <p>Every attempt ends with one {@link SecurityAuditEvent} handed to the {@link SecurityAuditStore}
 * after the decision is made and the password is wiped (slice 9). The store never blocks or throws,
 * and the event is built only from values this class always has, so the audit cannot change the
 * answer or its timing.
 */
@RequiredArgsConstructor
public final class LoginService implements LoginUseCase {
    @NonNull private final CustomerAuthenticationRepository customerAuthenticationRepository;
    @NonNull private final CredentialVerifierPort credentialVerifierPort;
    @NonNull private final CaptchaStore captchaStore;
    @NonNull private final SessionService sessionService;
    @NonNull private final TrustedDeviceService trustedDeviceService;
    @NonNull private final DeviceProofVerifier deviceProofVerifier;
    @NonNull private final LoginProofReplayStore loginProofReplayStore;
    @NonNull private final SecurityAuditStore securityAuditStore;
    @NonNull private final LockoutPolicy lockoutPolicy;
    /** Off until the apps sign the login proof; then a trusted device must prove its key for a full session. */
    private final boolean deviceProofRequired;
    @NonNull private final Clock clock;

    /**
     * The outcome of one attempt and what the audit needs to say about it: the reason (which names the
     * event type), the identity the attempt was about (null for an unknown user name or an outage)
     * and the session a success issued.
     */
    private record Decision(LoginResult result, SecurityEventReason reason, CustomerAuthentication identity,
                            SessionId sessionId) {
    }

    @Override
    public LoginResult login(LoginCommand command) {
        Decision decision;
        try {
            decision = decide(command);
        } catch (RepositoryUnavailableException failure) {
            decision = new Decision(new LoginResult.Unavailable(), SecurityEventReason.REPOSITORY, null, null);
        } catch (PartnerUnavailableException failure) {
            decision = new Decision(new LoginResult.Unavailable(), SecurityEventReason.PARTNER, null, null);
        } finally {
            command.password().clear();
        }
        securityAuditStore.record(auditEvent(command, decision));
        return decision.result();
    }

    private Decision decide(LoginCommand command) {
        Optional<CustomerAuthentication> foundIdentity =
                customerAuthenticationRepository.findByUserName(command.userName());

        if (foundIdentity.isPresent()) {
            CustomerAuthentication identity = foundIdentity.get();
            if (identity.lockout().isLocked(clock.instant())) {
                return new Decision(new LoginResult.AccountLocked(), SecurityEventReason.LOCKED, identity, null);
            }
            boolean captchaRequired = identity.lockout().captchaRequired(lockoutPolicy);
            if (captchaRequired && !captchaSolved(command, identity.customerId())) {
                return new Decision(new LoginResult.CaptchaRequired(), SecurityEventReason.CAPTCHA_REQUIRED, identity, null);
            }
        }

        // Keycloak is asked even for an unknown user, so both answers take similar time.
        VerificationResult verificationResult =
                credentialVerifierPort.verify(command.userName(), command.password());
        if (foundIdentity.isEmpty()) {
            return new Decision(new LoginResult.InvalidCredentials(), SecurityEventReason.UNKNOWN_USER, null, null);
        }
        CustomerAuthentication identity = foundIdentity.get();

        boolean passwordAccepted =
                verificationResult instanceof VerificationResult.Verified(var issuer, var subject)
                        && identity.isSameIdentity(issuer, subject);
        if (!passwordAccepted) {
            return recordFailure(identity);
        }

        if (!identity.isActive()) {
            return new Decision(new LoginResult.AccountNotReady(), SecurityEventReason.NOT_READY, identity, null);
        }

        if (identity.lockout().failedCount() > 0) {
            PasswordLockout resetLockout = identity.lockout().reset();
            customerAuthenticationRepository.saveLockoutIfCurrent(identity, resetLockout);
        }

        SessionId sessionId = sessionService.newSessionId();
        String correlationId = sessionId.toString();
        DeviceRouting deviceRouting = trustedDeviceService.routeAfterPassword(
                identity.customerId(),
                command.channel(),
                command.deviceId(),
                devicePossession(command),
                correlationId);

        IssuedSession issuedSession = switch (deviceRouting) {
            case DeviceRouting.FullSession() -> sessionService.issueActive(
                    sessionId,
                    identity.customerId(),
                    command.deviceId(),
                    command.channel(),
                    command.tokenEncryptionKey());
            case DeviceRouting.NeedTrust() -> sessionService.issueRestricted(
                    sessionId,
                    identity.customerId(),
                    command.deviceId(),
                    command.channel(),
                    command.tokenEncryptionKey());
        };
        Session session = issuedSession.session();

        LoginResult.Authenticated authenticated = new LoginResult.Authenticated(
                issuedSession.tokenEnvelope(),
                session.customerId(),
                session.status(),
                session.idleExpiresAt(),
                session.absoluteExpiresAt());
        SecurityEventReason sessionKind = session.status().full()
                ? SecurityEventReason.FULL_SESSION
                : SecurityEventReason.RESTRICTED_SESSION;
        return new Decision(authenticated, sessionKind, identity, session.id());
    }

    /**
     * How the routing learns whether this login holds the trusted row's key (slice 13). Not enforced: every
     * trusted primary device is taken at its word, as before this slice. Enforced: the proof must exist, verify
     * under the row's key for exactly this login's fields, and carry a nonce not seen before. The replay store
     * answering "not first" means a replay; the store not answering ends the login as unavailable.
     */
    private DevicePossession devicePossession(LoginCommand command) {
        if (!deviceProofRequired) {
            return device -> true;
        }
        return device -> {
            DeviceProof proof = command.deviceProof();
            if (proof == null || device.publicKey() == null) {
                return false;
            }

            DeviceProofBindings bindings = new DeviceProofBindings(
                    command.userName(),
                    command.channel(),
                    command.deviceId(),
                    command.platform(),
                    command.tokenEncryptionKey());
            DeviceProofVerifier.Outcome outcome = deviceProofVerifier.verify(device.publicKey(), proof, bindings);
            if (!(outcome instanceof DeviceProofVerifier.Outcome.Proven(var rememberUntil))) {
                return false;
            }

            return loginProofReplayStore.firstUse(proof.nonce(), rememberUntil);
        };
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
    private Decision recordFailure(CustomerAuthentication identity) {
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

        // The identity as it stands after this failure; if the write lost twice, the row as it was.
        CustomerAuthentication identityAfterFailure = savedIdentity.orElse(identity);
        if (identityAfterFailure.lockout().isLocked(now)) {
            return new Decision(new LoginResult.AccountLocked(), SecurityEventReason.LOCKED, identityAfterFailure, null);
        }
        return new Decision(new LoginResult.InvalidCredentials(), SecurityEventReason.WRONG_PASSWORD, identityAfterFailure, null);
    }

    /**
     * The decision as one audit row. Identifiers only: the customer when the user name matched, the
     * session a success issued, and the lockout count for anything but a success (a success has
     * just reset it).
     */
    private SecurityAuditEvent auditEvent(LoginCommand command, Decision decision) {
        CustomerAuthentication identity = decision.identity();
        boolean succeeded = decision.reason().type() == SecurityEventType.LOGIN_SUCCEEDED;
        Integer failedCount = identity == null || succeeded ? null : identity.lockout().failedCount();
        return SecurityAuditEvent.builder()
                .reason(decision.reason())
                .customerId(identity == null ? null : identity.customerId())
                .channel(command.channel())
                .platform(command.platform())
                .sessionId(decision.sessionId())
                .failedCount(failedCount)
                .occurredAt(clock.instant())
                .build();
    }
}
