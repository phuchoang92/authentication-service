package com.vpbank.dcp.infrastructure.adapter.in.web.trusteddevice;

import com.vpbank.dcp.core.session.TrustedDeviceCaller;
import com.vpbank.dcp.core.trusteddevice.TrustedDeviceService;
import com.vpbank.dcp.core.trusteddevice.BffCallerAssertions;
import com.vpbank.dcp.infrastructure.adapter.in.web.trusteddevice.dto.TrustedDeviceInitRequest;
import com.vpbank.dcp.infrastructure.adapter.in.web.trusteddevice.dto.TrustedDeviceResponse;
import com.vpbank.dcp.infrastructure.adapter.in.web.trusteddevice.dto.TrustedDeviceVerifyRequest;
import jakarta.validation.Valid;
import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Objects;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * init → verify → confirm of a NEED_TRUSTED_DEVICE login (draft doc 20 §4). Private to the
 * mTLS-authenticated Mobile BFF, which names the session, channel and device in its assertion.
 * A rejected assertion maps to 401 and an unrecordable use to 503 ({@code ApiErrorHandler}).
 */
@RestController
@ConditionalOnWebApplication
@Profile("integration")
@ConditionalOnProperty(prefix = "auth.native-session", name = "integration-activation-enabled",
        havingValue = "true")
@RequestMapping("/internal/v1/authentications/trusted-device")
public final class TrustedDeviceController {
    private static final String SCHEME = "Bearer ";
    private static final int MAX_ASSERTION_CHARS = 4096;

    private final BffCallerAssertions assertions;
    private final TrustedDeviceService trustedDevices;
    private final TrustedDeviceResponseMapper responses;
    private final Clock clock;

    public TrustedDeviceController(BffCallerAssertions assertions, TrustedDeviceService trustedDevices,
                                   TrustedDeviceResponseMapper responses, Clock clock) {
        this.assertions = Objects.requireNonNull(assertions);
        this.trustedDevices = Objects.requireNonNull(trustedDevices);
        this.responses = Objects.requireNonNull(responses);
        this.clock = Objects.requireNonNull(clock);
    }

    @PostMapping(path = "/init", consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<TrustedDeviceResponse> init(@RequestHeader HttpHeaders headers,
                                                      @Valid @RequestBody TrustedDeviceInitRequest body) {
        Instant now = clock.instant();
        return responses.init(trustedDevices.init(caller(headers, now), body.clientPublicKey(), now));
    }

    @PostMapping(path = "/verify", consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<TrustedDeviceResponse> verify(@RequestHeader HttpHeaders headers,
                                                        @Valid @RequestBody TrustedDeviceVerifyRequest body) {
        Instant now = clock.instant();
        return responses.verify(trustedDevices.verify(caller(headers, now), body.enrollmentId(),
                body.keyExchangeProof(), now));
    }

    @PostMapping(path = "/confirm", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> confirm(@RequestHeader HttpHeaders headers) {
        Instant now = clock.instant();
        return responses.confirm(trustedDevices.confirm(caller(headers, now), now));
    }

    /** Exactly one {@code Authorization: Bearer <BFF assertion>}, valid and not used before. */
    private TrustedDeviceCaller caller(HttpHeaders headers, Instant now) {
        List<String> values = headers.get(HttpHeaders.AUTHORIZATION);
        if (values == null || values.size() != 1 || values.getFirst() == null
                || !values.getFirst().startsWith(SCHEME)
                || values.getFirst().length() > SCHEME.length() + MAX_ASSERTION_CHARS
                || headers.containsHeader("DPoP")) {
            throw new RejectedBffCallerException();
        }
        return assertions.accept(values.getFirst().substring(SCHEME.length()), now)
                .orElseThrow(RejectedBffCallerException::new);
    }
}
