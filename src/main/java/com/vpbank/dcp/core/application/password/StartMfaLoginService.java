package com.vpbank.dcp.core.application.password;

import com.vpbank.dcp.core.port.in.password.PasswordLoginCommand;
import com.vpbank.dcp.core.port.out.mfa.MfaLoginRequest;
import com.vpbank.dcp.core.port.out.mfa.MfaStartResult;
import com.vpbank.dcp.core.port.out.mfa.MfaTransaction;
import com.vpbank.dcp.core.port.out.mfa.MfaTransactions;
import com.vpbank.dcp.core.port.out.mfa.MfaUnavailableException;
import com.vpbank.dcp.core.port.out.pending.PendingMfaLogin;
import com.vpbank.dcp.core.port.out.pending.PendingMfaLoginStore;
import com.vpbank.dcp.core.port.out.pending.PendingMfaLoginUnavailableException;
import com.vpbank.dcp.core.port.out.pending.PendingTokenCryptography;
import com.vpbank.dcp.core.port.out.pending.PreparedPendingToken;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.Objects;

/**
 * A trusted device that is not the primary one gets a restricted token and an MFA transaction.
 *
 * <p>Auth owns no factor: the MFA service creates the transaction, the App elevates it there, and
 * Auth only stores the returned identifier until the login is confirmed.
 */
public final class StartMfaLoginService {
    private final MfaTransactions mfa;
    private final PendingTokenCryptography cryptography;
    private final PendingMfaLoginStore pendingLogins;
    private final SecureRandom random;

    public StartMfaLoginService(MfaTransactions mfa, PendingTokenCryptography cryptography,
                                PendingMfaLoginStore pendingLogins, SecureRandom random) {
        this.mfa = Objects.requireNonNull(mfa);
        this.cryptography = Objects.requireNonNull(cryptography);
        this.pendingLogins = Objects.requireNonNull(pendingLogins);
        this.random = Objects.requireNonNull(random);
    }

    public StartMfaLoginResult start(PasswordLoginCommand command, AuthenticatedLogin accepted) {
        Objects.requireNonNull(command);
        Objects.requireNonNull(accepted);
        if (!command.journeyDeadline().isAfter(command.now())) {
            return new StartMfaLoginResult.Unavailable();
        }
        MfaStartResult started;
        try {
            started = mfa.start(new MfaLoginRequest(command.operation().operationId(),
                    accepted.subject(), accepted.customer().customerNumber(),
                    accepted.device().bindingId(), accepted.device().channel(),
                    command.journeyDeadline()));
        } catch (MfaUnavailableException failure) {
            // The transaction may already exist at the MFA service. Never start a second one.
            return new StartMfaLoginResult.Unavailable();
        }
        if (started instanceof MfaStartResult.NoUsableFactor) {
            return new StartMfaLoginResult.NoUsableFactor();
        }
        MfaTransaction transaction = ((MfaStartResult.Started) started).transaction();
        Instant expiresAt = transaction.expiresAt().isAfter(command.journeyDeadline())
                ? command.journeyDeadline() : transaction.expiresAt();
        if (!expiresAt.isAfter(command.now())) {
            return new StartMfaLoginResult.Unavailable();
        }
        String authenticationId = newId();
        var proofs = accepted.proof().proofs();
        PendingMfaLogin pending = new PendingMfaLogin(
                new PendingMfaLogin.Identity(command.operation().operationId(),
                        accepted.subject(), accepted.customer().customerNumber(),
                        accepted.device().bindingId(), accepted.device().channel(),
                        command.operation().installationId()),
                new PendingMfaLogin.Keys(proofs.requestKey().digest().base64Url(),
                        proofs.requestPublicJwk(), proofs.responsePublicJwk(),
                        proofs.deviceKeyThumbprint().base64Url()),
                new PendingMfaLogin.Mfa(authenticationId, transaction.transactionId(), expiresAt),
                new PendingMfaLogin.Versions(accepted.customer().statusVersion(),
                        accepted.device().securityVersion(), accepted.proof().generation()));
        PreparedPendingToken token = cryptography.issue(pending);
        try {
            return pendingLogins.create(token.lookup(), pending)
                    ? new StartMfaLoginResult.Ready(authenticationId, transaction.transactionId(),
                            expiresAt, token)
                    : new StartMfaLoginResult.Unavailable();
        } catch (PendingMfaLoginUnavailableException failure) {
            return new StartMfaLoginResult.Unavailable();
        }
    }

    private String newId() {
        byte[] bytes = new byte[24];
        random.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
