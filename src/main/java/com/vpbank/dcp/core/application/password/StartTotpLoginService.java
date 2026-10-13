package com.vpbank.dcp.core.application.password;

import com.vpbank.dcp.core.port.in.password.PasswordLoginCommand;
import com.vpbank.dcp.core.port.out.pending.PendingTokenCryptography;
import com.vpbank.dcp.core.port.out.pending.PendingTotpLogin;
import com.vpbank.dcp.core.port.out.pending.PendingTotpStore;
import com.vpbank.dcp.core.port.out.pending.PendingTotpUnavailableException;
import com.vpbank.dcp.core.port.out.pending.PreparedPendingToken;
import com.vpbank.dcp.core.port.out.totp.DeviceTotpAvailability;
import com.vpbank.dcp.core.port.out.totp.DeviceTotpUnavailableException;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Objects;

/** OTHER_TRUSTED receives a restricted token only when its TOTP credential is confirmed. */
public final class StartTotpLoginService {
    private final DeviceTotpAvailability credentials;
    private final PendingTokenCryptography cryptography;
    private final PendingTotpStore pendingLogins;
    private final SecureRandom random;
    private final Duration challengeLifetime;

    public StartTotpLoginService(DeviceTotpAvailability credentials,
                                 PendingTokenCryptography cryptography,
                                 PendingTotpStore pendingLogins, SecureRandom random,
                                 Duration challengeLifetime) {
        this.credentials = Objects.requireNonNull(credentials);
        this.cryptography = Objects.requireNonNull(cryptography);
        this.pendingLogins = Objects.requireNonNull(pendingLogins);
        this.random = Objects.requireNonNull(random);
        this.challengeLifetime = Objects.requireNonNull(challengeLifetime);
        if (challengeLifetime.isNegative() || challengeLifetime.isZero()
                || challengeLifetime.compareTo(Duration.ofMinutes(15)) > 0) {
            throw new InvalidTotpChallengePolicyException();
        }
    }

    public StartTotpLoginResult start(PasswordLoginCommand command,
                                      PasswordLoginAssessment.OtherTrusted accepted) {
        Objects.requireNonNull(command);
        Objects.requireNonNull(accepted);
        try {
            if (!credentials.hasActiveCredential(accepted.device().bindingId())) {
                return new StartTotpLoginResult.NeedsRecovery();
            }
        } catch (DeviceTotpUnavailableException failure) {
            return new StartTotpLoginResult.Unavailable();
        }
        Instant expiresAt = command.now().plus(challengeLifetime);
        if (expiresAt.isAfter(command.journeyDeadline())) {
            expiresAt = command.journeyDeadline();
        }
        if (!expiresAt.isAfter(command.now())) {
            return new StartTotpLoginResult.Unavailable();
        }
        String authenticationId = newId();
        String challengeId = newId();
        var proofs = accepted.proofs();
        PendingTotpLogin pending = new PendingTotpLogin(
                new PendingTotpLogin.Identity(command.operation().operationId(),
                        accepted.customerId(), accepted.customer().customerId(),
                        accepted.device().bindingId(), accepted.device().channel(),
                        command.operation().installationId()),
                new PendingTotpLogin.Keys(proofs.requestKey().digest().base64Url(),
                        proofs.requestPublicJwk(), proofs.responsePublicJwk(),
                        proofs.deviceKeyThumbprint().base64Url()),
                new PendingTotpLogin.Challenge(authenticationId, challengeId, expiresAt),
                new PendingTotpLogin.Versions(accepted.customer().statusVersion(),
                        accepted.device().securityVersion(), accepted.generation()));
        PreparedPendingToken token = cryptography.issue(pending);
        try {
            return pendingLogins.create(token.lookup(), pending)
                    ? new StartTotpLoginResult.Ready(authenticationId, challengeId, expiresAt, token)
                    : new StartTotpLoginResult.Unavailable();
        } catch (PendingTotpUnavailableException failure) {
            return new StartTotpLoginResult.Unavailable();
        }
    }

    private String newId() {
        byte[] bytes = new byte[24];
        random.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
