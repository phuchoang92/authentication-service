package com.vpbank.dcp.core.application.trusteddevice;

import com.vpbank.dcp.core.port.in.trusteddevice.TrustedDeviceCaller;
import com.vpbank.dcp.core.port.out.trusteddevice.KeyExchange;
import com.vpbank.dcp.core.port.out.trusteddevice.PreparedRestrictedSession;
import com.vpbank.dcp.core.port.out.trusteddevice.RestrictedSession;
import com.vpbank.dcp.core.port.out.trusteddevice.RestrictedSessionCryptography;
import com.vpbank.dcp.core.port.out.trusteddevice.RestrictedSessionStore;
import com.vpbank.dcp.core.port.out.trusteddevice.StoredRestrictedSession;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

/**
 * The restricted NEED_TRUSTED_DEVICE session: opened by a login that cannot become ACTIVE on
 * this device, then advanced by the trusted-device init, verify and confirm steps.
 *
 * <p>{@link #current} is the single place a caller is matched to its session. The store methods
 * throw {@code RestrictedSessionUnavailableException} when Valkey cannot answer.
 */
public final class TrustedDeviceSessions {
    private static final Duration MINIMUM_LIFETIME = Duration.ofMinutes(1);
    private static final Duration MAXIMUM_LIFETIME = Duration.ofMinutes(30);

    private final RestrictedSessionCryptography cryptography;
    private final RestrictedSessionStore store;
    private final Duration lifetime;

    public TrustedDeviceSessions(RestrictedSessionCryptography cryptography,
                                 RestrictedSessionStore store, Duration lifetime) {
        this.cryptography = Objects.requireNonNull(cryptography);
        this.store = Objects.requireNonNull(store);
        this.lifetime = Objects.requireNonNull(lifetime);
        if (lifetime.compareTo(MINIMUM_LIFETIME) < 0 || lifetime.compareTo(MAXIMUM_LIFETIME) > 0) {
            throw new InvalidTrustedDevicePolicyException();
        }
    }

    public RestrictedSessionResult open(RestrictedSession session, Instant now) {
        Objects.requireNonNull(session);
        Objects.requireNonNull(now);
        // The replay markers of this login were reserved under this generation; a Valkey
        // restart in between must not let the login continue.
        if (!currentGeneration(session.generation())) {
            return new RestrictedSessionResult.Unavailable();
        }
        PreparedRestrictedSession prepared = cryptography.prepare(session, now.plus(lifetime));
        return store.create(prepared)
                ? new RestrictedSessionResult.Opened(prepared)
                : new RestrictedSessionResult.Unavailable();
    }

    /**
     * The caller's session only if the BFF-asserted channel and device ID are the ones that
     * logged in, and Valkey has not restarted since. Anything else looks like no session.
     */
    public Optional<StoredRestrictedSession> current(TrustedDeviceCaller caller) {
        Objects.requireNonNull(caller);
        return store.find(caller.session())
                .filter(session -> session.channel().equals(caller.channel()))
                .filter(session -> cryptography.deviceIdDigest(session.owner(), session.channel(),
                        caller.deviceId()).equals(session.deviceIdDigest()))
                .filter(session -> currentGeneration(session.generation()));
    }

    public boolean beginKeyExchange(TrustedDeviceCaller caller, KeyExchange exchange) {
        return store.beginKeyExchange(caller.session(), exchange);
    }

    public int recordVerifyAttempt(TrustedDeviceCaller caller) {
        return store.recordVerifyAttempt(caller.session());
    }

    public boolean recordMfaTransaction(TrustedDeviceCaller caller, String mfaTransactionId) {
        return store.recordMfaTransaction(caller.session(), mfaTransactionId);
    }

    /** Ends the session. True for exactly one caller, which alone may finish the trust. */
    public boolean end(TrustedDeviceCaller caller) {
        return store.consume(caller.session());
    }

    private boolean currentGeneration(UUID expected) {
        return store.currentGeneration().map(expected::equals).orElse(false);
    }
}
