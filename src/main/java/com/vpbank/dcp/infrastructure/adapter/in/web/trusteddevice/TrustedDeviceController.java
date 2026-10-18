package com.vpbank.dcp.infrastructure.adapter.in.web.trusteddevice;

import com.vpbank.dcp.core.port.in.trusteddevice.TrustedDeviceCaller;
import com.vpbank.dcp.core.port.in.trusteddevice.TrustedDeviceUseCase;
import com.vpbank.dcp.infrastructure.adapter.in.web.trusteddevice.dto.TrustedDeviceInitRequest;
import com.vpbank.dcp.infrastructure.adapter.in.web.trusteddevice.dto.TrustedDeviceResponse;
import com.vpbank.dcp.infrastructure.adapter.in.web.trusteddevice.dto.TrustedDeviceVerifyRequest;
import jakarta.validation.Valid;
import java.time.Clock;
import java.time.Instant;
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
import tools.jackson.databind.json.JsonMapper;

/**
 * init → verify → confirm of a NEED_TRUSTED_DEVICE login (draft doc 20 §4). Private to the
 * mTLS-authenticated Mobile BFF, which names the session, channel and device in its assertion.
 */
@RestController
@ConditionalOnWebApplication
@Profile("integration")
@ConditionalOnProperty(prefix = "auth.native-session", name = "integration-activation-enabled",
        havingValue = "true")
@RequestMapping("/internal/v1/authentications/trusted-device")
public final class TrustedDeviceController {
    private final BffCallers callers;
    private final TrustedDeviceUseCase trustedDevices;
    private final TrustedDeviceResponseMapper responses;
    private final JsonMapper json;
    private final Clock clock;

    public TrustedDeviceController(BffCallers callers, TrustedDeviceUseCase trustedDevices,
                                   TrustedDeviceResponseMapper responses, JsonMapper json,
                                   Clock clock) {
        this.callers = Objects.requireNonNull(callers);
        this.trustedDevices = Objects.requireNonNull(trustedDevices);
        this.responses = Objects.requireNonNull(responses);
        this.json = Objects.requireNonNull(json);
        this.clock = Objects.requireNonNull(clock);
    }

    @PostMapping(path = "/init", consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<TrustedDeviceResponse> init(@RequestHeader HttpHeaders headers,
                                                      @Valid @RequestBody TrustedDeviceInitRequest body) {
        Instant now = clock.instant();
        TrustedDeviceCaller caller = callers.require(headers, now);
        String devicePublicJwk = body.devicePublicJwk() == null
                ? null : json.writeValueAsString(body.devicePublicJwk());
        return responses.init(trustedDevices.init(caller, devicePublicJwk, now));
    }

    @PostMapping(path = "/verify", consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<TrustedDeviceResponse> verify(@RequestHeader HttpHeaders headers,
                                                        @Valid @RequestBody TrustedDeviceVerifyRequest body) {
        Instant now = clock.instant();
        return responses.verify(trustedDevices.verify(callers.require(headers, now),
                body.challengeResponse(), now));
    }

    @PostMapping(path = "/confirm", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> confirm(@RequestHeader HttpHeaders headers) {
        Instant now = clock.instant();
        return responses.confirm(trustedDevices.confirm(callers.require(headers, now), now));
    }
}
