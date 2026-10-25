package com.vpbank.dcp.auth.application.service;

import com.vpbank.dcp.auth.application.port.in.LoginCommand;
import com.vpbank.dcp.auth.application.port.in.LoginResult;
import com.vpbank.dcp.auth.application.port.in.LoginUseCase;
import com.vpbank.dcp.auth.application.port.out.CredentialVerifierPort;
import com.vpbank.dcp.auth.application.port.out.CredentialVerifierPort.VerificationResult;
import com.vpbank.dcp.auth.application.port.out.CustomerAuthentication;
import com.vpbank.dcp.auth.application.port.out.CustomerAuthenticationRepository;
import com.vpbank.dcp.auth.application.port.out.OpaqueTokenGenerator;
import com.vpbank.dcp.auth.application.port.out.PartnerUnavailableException;
import com.vpbank.dcp.auth.application.port.out.RepositoryUnavailableException;
import com.vpbank.dcp.auth.application.port.out.SessionStore;
import com.vpbank.dcp.auth.application.port.out.TokenEnvelopeSealer;
import com.vpbank.dcp.auth.domain.model.OpaqueToken;
import com.vpbank.dcp.auth.domain.model.Session;
import com.vpbank.dcp.auth.domain.model.SessionId;
import com.vpbank.dcp.auth.domain.model.SessionPolicy;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;

import java.time.Clock;
import java.util.Optional;
import java.util.function.Supplier;

/**
 * Password login (slice 2): identity row → Keycloak password check → same issuer/subject →
 * new ACTIVE session in the store → token sealed to the app's key.
 *
 * <p>Unknown user and wrong password give the same answer, so nothing reveals whether an account
 * exists; Keycloak is still asked for an unknown user so the two paths take similar time. The
 * password is wiped as soon as the provider has answered. Trusted-device and lockout rules are
 * later slices; this service records the device ID and nothing more.
 */
@RequiredArgsConstructor
public final class LoginService implements LoginUseCase {
    @NonNull private final CustomerAuthenticationRepository identities;
    @NonNull private final CredentialVerifierPort credentials;
    @NonNull private final SessionStore sessions;
    @NonNull private final TokenEnvelopeSealer sealer;
    @NonNull private final OpaqueTokenGenerator tokens;
    @NonNull private final Supplier<SessionId> sessionIds;
    @NonNull private final SessionPolicy policy;
    @NonNull private final Clock clock;

    @Override
    public LoginResult login(LoginCommand command) {
        try {
            Optional<CustomerAuthentication> identity = identities.findByUserName(command.userName());
            VerificationResult verified = credentials.verify(command.userName(), command.password());
            if (identity.isEmpty() || !(verified instanceof VerificationResult.Verified(var issuer, var subject))
                    || !identity.get().isSameIdentity(issuer, subject)) {
                return new LoginResult.InvalidCredentials();
            }
            if (!identity.get().isActive()) {
                return new LoginResult.AccountNotReady();
            }
            Session session = Session.start(sessionIds.get(), identity.get().customerId(), command.deviceId(),
                    command.channel(), clock.instant(), policy);
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
