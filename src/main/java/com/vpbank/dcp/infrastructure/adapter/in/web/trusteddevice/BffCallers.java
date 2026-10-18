package com.vpbank.dcp.infrastructure.adapter.in.web.trusteddevice;

import com.vpbank.dcp.core.port.in.trusteddevice.TrustedDeviceCaller;
import com.vpbank.dcp.core.port.out.replay.AssertionReplay;
import com.vpbank.dcp.core.port.out.replay.ReplayAuthorityUnavailableException;
import com.vpbank.dcp.core.port.out.replay.ReplayReservation;
import com.vpbank.dcp.infrastructure.adapter.out.crypto.BffAssertionVerifier;
import com.vpbank.dcp.infrastructure.adapter.out.crypto.InvalidCryptographicInputException;
import com.vpbank.dcp.infrastructure.adapter.out.crypto.VerifiedBffAssertion;
import java.time.Instant;
import java.util.List;
import java.util.Objects;
import org.springframework.http.HttpHeaders;

/**
 * Turns {@code Authorization: Bearer <BFF assertion>} into the caller of a trusted-device step
 * (draft doc 20 §4). Each assertion is accepted once.
 */
public final class BffCallers {
    private static final String SCHEME = "Bearer ";
    private static final int MAX_ASSERTION_CHARS = 4096;

    private final BffAssertionVerifier assertions;
    private final AssertionReplay replay;

    public BffCallers(BffAssertionVerifier assertions, AssertionReplay replay) {
        this.assertions = Objects.requireNonNull(assertions);
        this.replay = Objects.requireNonNull(replay);
    }

    /**
     * Throws {@link RejectedBffCallerException} for anything but one fresh, valid assertion, and
     * {@link ReplayAuthorityUnavailableException} when its single use cannot be recorded.
     */
    public TrustedDeviceCaller require(HttpHeaders headers, Instant now) {
        Objects.requireNonNull(headers);
        Objects.requireNonNull(now);
        List<String> values = headers.get(HttpHeaders.AUTHORIZATION);
        if (values == null || values.size() != 1 || values.getFirst() == null
                || !values.getFirst().startsWith(SCHEME)
                || values.getFirst().length() > SCHEME.length() + MAX_ASSERTION_CHARS
                || headers.containsHeader("DPoP")) {
            throw new RejectedBffCallerException();
        }
        VerifiedBffAssertion verified;
        try {
            verified = assertions.verify(values.getFirst().substring(SCHEME.length()), now);
        } catch (InvalidCryptographicInputException failure) {
            throw new RejectedBffCallerException(failure);
        }
        ReplayReservation reservation = replay.reserve(verified.assertionIdDigest(), verified.expiresAt());
        return switch (reservation) {
            case RESERVED -> new TrustedDeviceCaller(verified.session(), verified.channel(),
                    verified.deviceId());
            case REPLAYED -> throw new RejectedBffCallerException();
            case AUTHORITY_CLOSED -> throw new ReplayAuthorityUnavailableException();
        };
    }
}
