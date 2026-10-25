package com.vpbank.dcp.core.trusteddevice;

import com.vpbank.dcp.core.session.TrustedDeviceSessions;
import com.vpbank.dcp.core.security.Digest32;
import com.vpbank.dcp.core.session.TrustedDeviceCaller;
import com.vpbank.dcp.core.session.KeyExchange;
import com.vpbank.dcp.core.session.RestrictedSession;
import com.vpbank.dcp.core.session.RestrictedSessionStep;
import com.vpbank.dcp.core.session.RestrictedSessionUnavailableException;
import com.vpbank.dcp.core.session.StoredRestrictedSession;
import com.vpbank.dcp.core.session.TrustTarget;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/**
 * init exchanges keys, verify proves the device key and opens the MFA transaction, confirm
 * checks MFA and commits the trust. Identity is proven by FACE at the MFA service; init only
 * exchanges keys (draft doc 20 §4).
 *
 * <p>Each step requires the previous one, and each advance succeeds at most once, so steps
 * cannot be skipped, repeated or raced.
 */
public final class TrustedDeviceService {
    private final TrustedDeviceSessions sessions;
    private final ServerKeyExchange keys;
    private final MfaTransactions mfa;
    private final TrustedDeviceRecords records;
    private final TrustedSessionIssuer issuer;
    private final int maximumVerifyAttempts;

    public TrustedDeviceService(TrustedDeviceSessions sessions, ServerKeyExchange keys,
                                MfaTransactions mfa, TrustedDeviceRecords records,
                                TrustedSessionIssuer issuer, int maximumVerifyAttempts) {
        this.sessions = Objects.requireNonNull(sessions);
        this.keys = Objects.requireNonNull(keys);
        this.mfa = Objects.requireNonNull(mfa);
        this.records = Objects.requireNonNull(records);
        this.issuer = Objects.requireNonNull(issuer);
        if (maximumVerifyAttempts < 1 || maximumVerifyAttempts > 10) {
            throw new IllegalArgumentException("Trusted-device policy value is out of range");
        }
        this.maximumVerifyAttempts = maximumVerifyAttempts;
    }

    /** {@code clientPublicKey} is required for a new device and must be absent for a known one. */
    public InitTrustedDeviceResult init(TrustedDeviceCaller caller, String clientPublicKey,
                                        Instant now) {
        Objects.requireNonNull(caller);
        try {
            StoredRestrictedSession session = sessions.current(caller).orElse(null);
            if (session == null || session.progress().step() != RestrictedSessionStep.OPEN) {
                return new InitTrustedDeviceResult.Rejected();
            }
            DeviceKeyMaterial deviceKey = deviceKey(session, clientPublicKey);
            if (deviceKey == null) {
                return new InitTrustedDeviceResult.Rejected();
            }
            RestrictedSession login = session.login();
            if (!(keys.begin(deviceKey, login.customer().owner(), login.device().channel())
                    instanceof KeyExchangeStart.Started(var exchange, var suite, var challenge))
                    || !keptKey(session, exchange)
                    || !sessions.beginKeyExchange(caller, exchange)) {
                return new InitTrustedDeviceResult.Rejected();
            }
            return new InitTrustedDeviceResult.Started(exchange.enrollmentId(), suite,
                    exchange.serverPublicKey(), challenge);
        } catch (RestrictedSessionUnavailableException | TrustedDeviceRecordsUnavailableException failure) {
            return new InitTrustedDeviceResult.Unavailable();
        }
    }

    /** {@code enrollmentId} must be the one init returned for this session. */
    public VerifyTrustedDeviceResult verify(TrustedDeviceCaller caller, UUID enrollmentId,
                                            String keyExchangeProof, Instant now) {
        Objects.requireNonNull(caller);
        try {
            StoredRestrictedSession session = sessions.current(caller).orElse(null);
            if (session == null || session.progress().step() != RestrictedSessionStep.KEY_EXCHANGE) {
                return new VerifyTrustedDeviceResult.Rejected();
            }
            // Counted before the answer is checked, so guesses cannot outrun the limit.
            int attempts = sessions.recordVerifyAttempt(caller);
            if (attempts < 1 || attempts > maximumVerifyAttempts) {
                sessions.end(caller);
                return new VerifyTrustedDeviceResult.Rejected();
            }
            // A foreign enrollment ID counts like a wrong proof: it is one more guess.
            KeyExchange exchange = session.progress().keyExchange();
            RestrictedSession login = session.login();
            if (!exchange.enrollmentId().equals(enrollmentId)
                    || !keys.answers(exchange, login.customer().owner(), login.device().channel(),
                            keyExchangeProof)) {
                if (attempts == maximumVerifyAttempts) {
                    sessions.end(caller);
                    return new VerifyTrustedDeviceResult.Rejected();
                }
                return new VerifyTrustedDeviceResult.WrongChallenge(maximumVerifyAttempts - attempts);
            }
            return startMfa(caller, session);
        } catch (RestrictedSessionUnavailableException failure) {
            return new VerifyTrustedDeviceResult.Unavailable();
        }
    }

    public ConfirmTrustedDeviceResult confirm(TrustedDeviceCaller caller, Instant now) {
        Objects.requireNonNull(caller);
        Objects.requireNonNull(now);
        try {
            StoredRestrictedSession session = sessions.current(caller).orElse(null);
            if (session == null || session.progress().step() != RestrictedSessionStep.MFA) {
                return new ConfirmTrustedDeviceResult.Rejected();
            }
            MfaCheckResult checked;
            try {
                checked = mfa.check(new MfaTrustCheck(session.progress().mfaTransactionId(),
                        mfaRequest(session)));
            } catch (MfaUnavailableException failure) {
                return new ConfirmTrustedDeviceResult.Unavailable();
            }
            return switch (checked) {
                case MfaCheckResult.Passed(var receiptDigest) ->
                        commit(caller, session, receiptDigest, now);
                // Kept: the App elevates at the MFA service and confirms again.
                case MfaCheckResult.Pending() -> new ConfirmTrustedDeviceResult.MfaPending();
                case MfaCheckResult.Expired() -> {
                    sessions.end(caller);
                    yield new ConfirmTrustedDeviceResult.Expired();
                }
                case MfaCheckResult.Failed(), MfaCheckResult.InvalidReceipt() -> {
                    sessions.end(caller);
                    yield new ConfirmTrustedDeviceResult.Rejected();
                }
            };
        } catch (RestrictedSessionUnavailableException failure) {
            return new ConfirmTrustedDeviceResult.Unavailable();
        }
    }

    private VerifyTrustedDeviceResult startMfa(TrustedDeviceCaller caller,
                                               StoredRestrictedSession session) {
        MfaStartResult started;
        try {
            started = mfa.start(mfaRequest(session));
        } catch (MfaUnavailableException failure) {
            // The session stays at KEY_EXCHANGE; a retry starts the same MFA transaction.
            return new VerifyTrustedDeviceResult.Unavailable();
        }
        return switch (started) {
            case MfaStartResult.Started(var transactionId, var expiresAt) ->
                    sessions.recordMfaTransaction(caller, transactionId)
                            ? new VerifyTrustedDeviceResult.MfaRequired(transactionId)
                            : new VerifyTrustedDeviceResult.Rejected();
            case MfaStartResult.NoUsableFactor() -> {
                sessions.end(caller);
                yield new VerifyTrustedDeviceResult.NoUsableFactor();
            }
        };
    }

    /**
     * The session is ended first: exactly one confirm may commit, and a trust whose commit then
     * fails needs a new login rather than a second chance on the same MFA result.
     */
    private ConfirmTrustedDeviceResult commit(TrustedDeviceCaller caller,
                                              StoredRestrictedSession session,
                                              Digest32 receiptDigest,
                                              Instant now) {
        if (!sessions.end(caller)) {
            return new ConfirmTrustedDeviceResult.Rejected();
        }
        KeyExchange exchange = session.progress().keyExchange();
        RestrictedSession login = session.login();
        TrustActivationResult activated;
        try {
            activated = records.activate(new TrustActivation(login, exchange, caller.deviceId(),
                    receiptDigest, now));
        } catch (TrustedDeviceRecordsUnavailableException failure) {
            return new ConfirmTrustedDeviceResult.Unavailable();
        }
        return switch (activated) {
            case TrustActivationResult.Activated(var binding) ->
                    issuer.issue(login, binding, caller.deviceId(), now);
            case TrustActivationResult.Rejected() -> new ConfirmTrustedDeviceResult.Rejected();
        };
    }

    /** A new device presents its key; a known one keeps the key stored at trust time. */
    private DeviceKeyMaterial deviceKey(StoredRestrictedSession session, String clientPublicKey) {
        RestrictedSession login = session.login();
        return switch (login.device().target()) {
            case TrustTarget.NewDevice() -> clientPublicKey == null || clientPublicKey.isBlank()
                    ? null : new DeviceKeyMaterial.Presented(clientPublicKey);
            case TrustTarget.KnownDevice known -> clientPublicKey != null
                    ? null
                    : records.storedKey(login.customer().owner(), login.device().channel(),
                                    known.bindingId())
                            .<DeviceKeyMaterial>map(DeviceKeyMaterial.Stored::new).orElse(null);
        };
    }

    /** A known device must be challenged with exactly the key pinned at login. */
    private static boolean keptKey(StoredRestrictedSession session, KeyExchange exchange) {
        return switch (session.login().device().target()) {
            case TrustTarget.NewDevice() -> true;
            case TrustTarget.KnownDevice known ->
                    known.deviceKeyThumbprint().equals(exchange.deviceKeyThumbprint());
        };
    }

    private static MfaTrustRequest mfaRequest(StoredRestrictedSession session) {
        RestrictedSession login = session.login();
        return new MfaTrustRequest(login.operationId(), login.customer().number(),
                login.device().channel(), session.expiresAt());
    }
}
