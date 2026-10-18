package com.vpbank.dcp.core.application.trusteddevice;

import com.vpbank.dcp.core.domain.security.Digest32;
import com.vpbank.dcp.core.port.in.trusteddevice.ConfirmTrustedDeviceResult;
import com.vpbank.dcp.core.port.in.trusteddevice.InitTrustedDeviceResult;
import com.vpbank.dcp.core.port.in.trusteddevice.TrustedDeviceCaller;
import com.vpbank.dcp.core.port.in.trusteddevice.TrustedDeviceUseCase;
import com.vpbank.dcp.core.port.in.trusteddevice.VerifyTrustedDeviceResult;
import com.vpbank.dcp.core.port.out.mfa.MfaCheckResult;
import com.vpbank.dcp.core.port.out.mfa.MfaStartResult;
import com.vpbank.dcp.core.port.out.mfa.MfaTransactions;
import com.vpbank.dcp.core.port.out.mfa.MfaTrustCheck;
import com.vpbank.dcp.core.port.out.mfa.MfaTrustRequest;
import com.vpbank.dcp.core.port.out.mfa.MfaUnavailableException;
import com.vpbank.dcp.core.port.out.trusteddevice.DeviceKeyMaterial;
import com.vpbank.dcp.core.port.out.trusteddevice.KeyExchange;
import com.vpbank.dcp.core.port.out.trusteddevice.KeyExchangeStart;
import com.vpbank.dcp.core.port.out.trusteddevice.RestrictedSessionStep;
import com.vpbank.dcp.core.port.out.trusteddevice.RestrictedSessionUnavailableException;
import com.vpbank.dcp.core.port.out.trusteddevice.ServerKeyExchange;
import com.vpbank.dcp.core.port.out.trusteddevice.StoredRestrictedSession;
import com.vpbank.dcp.core.port.out.trusteddevice.TrustActivation;
import com.vpbank.dcp.core.port.out.trusteddevice.TrustActivationResult;
import com.vpbank.dcp.core.port.out.trusteddevice.TrustTarget;
import com.vpbank.dcp.core.port.out.trusteddevice.TrustedDeviceRecords;
import com.vpbank.dcp.core.port.out.trusteddevice.TrustedDeviceRecordsUnavailableException;
import java.time.Instant;
import java.util.Objects;

/**
 * init exchanges keys, verify proves the device key and opens the MFA transaction, confirm
 * checks MFA and commits the trust. Identity is proven by FACE at the MFA service; init only
 * exchanges keys (draft doc 20 §4).
 *
 * <p>Each step requires the previous one, and each advance succeeds at most once, so steps
 * cannot be skipped, repeated or raced.
 */
public final class TrustedDeviceService implements TrustedDeviceUseCase {
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
            throw new InvalidTrustedDevicePolicyException();
        }
        this.maximumVerifyAttempts = maximumVerifyAttempts;
    }

    @Override
    public InitTrustedDeviceResult init(TrustedDeviceCaller caller, String devicePublicJwk,
                                        Instant now) {
        Objects.requireNonNull(caller);
        try {
            StoredRestrictedSession session = sessions.current(caller).orElse(null);
            if (session == null || session.step() != RestrictedSessionStep.OPEN) {
                return new InitTrustedDeviceResult.Rejected();
            }
            DeviceKeyMaterial deviceKey = deviceKey(session, devicePublicJwk);
            if (deviceKey == null) {
                return new InitTrustedDeviceResult.Rejected();
            }
            if (!(keys.begin(deviceKey, session.owner(), session.channel())
                    instanceof KeyExchangeStart.Started(var exchange, var challengeJwe))
                    || !keptKey(session, exchange)
                    || !sessions.beginKeyExchange(caller, exchange)) {
                return new InitTrustedDeviceResult.Rejected();
            }
            return new InitTrustedDeviceResult.Started(exchange.serverPublicJwk(), challengeJwe);
        } catch (RestrictedSessionUnavailableException | TrustedDeviceRecordsUnavailableException failure) {
            return new InitTrustedDeviceResult.Unavailable();
        }
    }

    @Override
    public VerifyTrustedDeviceResult verify(TrustedDeviceCaller caller, String challengeResponseJwe,
                                            Instant now) {
        Objects.requireNonNull(caller);
        try {
            StoredRestrictedSession session = sessions.current(caller).orElse(null);
            if (session == null || session.step() != RestrictedSessionStep.KEY_EXCHANGE) {
                return new VerifyTrustedDeviceResult.Rejected();
            }
            // Counted before the answer is checked, so guesses cannot outrun the limit.
            int attempts = sessions.recordVerifyAttempt(caller);
            if (attempts < 1 || attempts > maximumVerifyAttempts) {
                sessions.end(caller);
                return new VerifyTrustedDeviceResult.Rejected();
            }
            if (!keys.answers(session.keyExchange(), session.owner(), session.channel(),
                    challengeResponseJwe)) {
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

    @Override
    public ConfirmTrustedDeviceResult confirm(TrustedDeviceCaller caller, Instant now) {
        Objects.requireNonNull(caller);
        Objects.requireNonNull(now);
        try {
            StoredRestrictedSession session = sessions.current(caller).orElse(null);
            if (session == null || session.step() != RestrictedSessionStep.MFA) {
                return new ConfirmTrustedDeviceResult.Rejected();
            }
            MfaCheckResult checked;
            try {
                checked = mfa.check(new MfaTrustCheck(session.mfaTransactionId(), mfaRequest(session)));
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
        KeyExchange exchange = session.keyExchange();
        TrustActivationResult activated;
        try {
            activated = records.activate(new TrustActivation(session.operationId(), session.owner(),
                    session.customerStatusVersion(), session.channel(), session.target(),
                    session.platform(), exchange.deviceKeyThumbprint(), exchange.devicePublicJwk(),
                    exchange.serverKey(), caller.deviceId(), receiptDigest, now));
        } catch (TrustedDeviceRecordsUnavailableException failure) {
            return new ConfirmTrustedDeviceResult.Unavailable();
        }
        return switch (activated) {
            case TrustActivationResult.Activated(var binding) ->
                    issuer.issue(session, binding, caller.deviceId(), now);
            case TrustActivationResult.Rejected() -> new ConfirmTrustedDeviceResult.Rejected();
        };
    }

    /** A new device presents its key; a known one keeps the key stored at trust time. */
    private DeviceKeyMaterial deviceKey(StoredRestrictedSession session, String devicePublicJwk) {
        return switch (session.target()) {
            case TrustTarget.NewDevice() -> devicePublicJwk == null || devicePublicJwk.isBlank()
                    ? null : new DeviceKeyMaterial.Presented(devicePublicJwk);
            case TrustTarget.KnownDevice known -> devicePublicJwk != null
                    ? null
                    : records.storedKey(session.owner(), session.channel(), known.bindingId())
                            .<DeviceKeyMaterial>map(DeviceKeyMaterial.Stored::new).orElse(null);
        };
    }

    /** A known device must be challenged with exactly the key pinned at login. */
    private static boolean keptKey(StoredRestrictedSession session, KeyExchange exchange) {
        return switch (session.target()) {
            case TrustTarget.NewDevice() -> true;
            case TrustTarget.KnownDevice known ->
                    known.deviceKeyThumbprint().equals(exchange.deviceKeyThumbprint());
        };
    }

    private static MfaTrustRequest mfaRequest(StoredRestrictedSession session) {
        return new MfaTrustRequest(session.operationId(), session.customerNumber(),
                session.channel(), session.expiresAt());
    }
}
