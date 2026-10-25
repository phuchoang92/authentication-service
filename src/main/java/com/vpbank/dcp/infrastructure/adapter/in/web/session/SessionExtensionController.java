package com.vpbank.dcp.infrastructure.adapter.in.web.session;

import com.vpbank.dcp.core.security.Digest32;
import com.vpbank.dcp.core.security.RequestKeyThumbprint;
import com.vpbank.dcp.core.session.ExtendSessionCommand;
import com.vpbank.dcp.core.session.ExtendSessionResult;
import com.vpbank.dcp.core.session.ExtendSessionService;
import com.vpbank.dcp.infrastructure.adapter.in.web.error.ApiError;
import com.vpbank.dcp.infrastructure.adapter.in.web.session.dto.SessionExtensionRequest;
import com.vpbank.dcp.infrastructure.adapter.in.web.session.dto.SessionExtensionResponse;
import com.vpbank.dcp.infrastructure.config.properties.SessionExtensionProperties;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.context.annotation.Profile;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

/**
 * BFF → Auth idle sliding after the BFF admitted one App request (flow 16). Spring Security
 * already requires an allowlisted mTLS workload; this route additionally accepts only the
 * configured Mobile BFF URI. Integration only.
 */
@RestController
@ConditionalOnWebApplication
@Profile("integration")
@ConditionalOnProperty(prefix = "auth.native-session", name = "integration-activation-enabled",
        havingValue = "true")
@RequestMapping("/internal/v1/auth/sessions")
public final class SessionExtensionController {
    private static final Logger LOG = LoggerFactory.getLogger(SessionExtensionController.class);

    private final ExtendSessionService sessions;
    private final String bffWorkloadUri;

    public SessionExtensionController(ExtendSessionService sessions,
                                      SessionExtensionProperties properties) {
        this.sessions = Objects.requireNonNull(sessions);
        this.bffWorkloadUri = Objects.requireNonNull(properties.bffWorkloadUri());
    }

    @PostMapping(path = "/extend", consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> extend(Principal workload,
                                    @Valid @RequestBody SessionExtensionRequest body) {
        if (workload == null || !bffWorkloadUri.equals(workload.getName())) {
            return error(HttpStatus.FORBIDDEN, "REQUEST_REJECTED", "The request was rejected");
        }
        Optional<ExtendSessionCommand> command = command(body);
        if (command.isEmpty()) {
            return error(HttpStatus.BAD_REQUEST, "REQUEST_REJECTED", "The request was rejected");
        }
        return switch (sessions.extend(command.get())) {
            case ExtendSessionResult.Extended(var deadlines) -> ResponseEntity.ok()
                    .cacheControl(CacheControl.noStore())
                    .body(new SessionExtensionResponse("EXTENDED",
                            deadlines.idleExpiresAt().toString(),
                            deadlines.absoluteExpiresAt().toString()));
            case ExtendSessionResult.NotExtended(var reason) -> switch (reason) {
                case INVALID_REQUEST ->
                        error(HttpStatus.BAD_REQUEST, "REQUEST_REJECTED", "The request was rejected");
                case GONE -> error(HttpStatus.GONE, "SESSION_EXPIRED", "The session has ended");
                case CONFLICT -> error(HttpStatus.CONFLICT, "SESSION_CHANGED", "The session changed");
                case UNAVAILABLE -> error(HttpStatus.SERVICE_UNAVAILABLE, "TEMPORARILY_UNAVAILABLE",
                        "Please try again later");
            };
        };
    }

    /** Empty when a value passes the wire pattern but is not a valid digest, ID or instant. */
    private static Optional<ExtendSessionCommand> command(SessionExtensionRequest body) {
        try {
            return Optional.of(new ExtendSessionCommand(UUID.fromString(body.sessionId()),
                    new RequestKeyThumbprint(Digest32.fromBase64Url(body.requestKeyJkt())),
                    body.routeId(), UUID.fromString(body.admissionId()),
                    Instant.parse(body.admittedAt())));
        } catch (IllegalArgumentException | DateTimeParseException invalid) {
            return Optional.empty();
        }
    }

    private static ResponseEntity<ApiError> error(HttpStatus status, String code, String message) {
        UUID correlationId = UUID.randomUUID();
        if (status.is5xxServerError()) {
            LOG.warn("Session extension unavailable: correlationId={}", correlationId);
        }
        return ResponseEntity.status(status).cacheControl(CacheControl.noStore())
                .body(new ApiError(code, message, correlationId));
    }
}
