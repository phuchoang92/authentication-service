package com.vpbank.dcp.infrastructure.adapter.in.web.password;

import com.vpbank.dcp.core.application.password.PasswordAuthenticationResult;
import com.vpbank.dcp.core.port.out.session.PreparedPasswordSession;
import java.time.Clock;
import java.time.Duration;
import java.util.Map;
import java.util.UUID;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

/** Only encrypted App delivery fields leave the private Auth endpoint. */
public final class PasswordHttpResponseMapper {
    private final Clock clock;

    public PasswordHttpResponseMapper(Clock clock) {
        this.clock = clock;
    }

    public ResponseEntity<?> map(UUID operationId, PasswordAuthenticationResult result) {
        if (result instanceof PasswordAuthenticationResult.Active active) {
            PreparedPasswordSession session = active.session();
            if (!clock.instant().isBefore(session.deadlines().idleExpiresAt())) {
                return problem(HttpStatus.SERVICE_UNAVAILABLE, "TEMPORARILY_UNAVAILABLE");
            }
            long seconds = Math.max(1, Duration.between(clock.instant(),
                    session.deadlines().absoluteExpiresAt()).toSeconds());
            var facts = session.facts();
            Map<String, Object> body = Map.of(
                    "status", "ACTIVE",
                    "tokenEnvelope", session.tokenEnvelope(),
                    "receipt", session.receipt(),
                    "expires_in", Math.min(seconds, 3600),
                    "scope", "banking",
                    "session", Map.of("idleExpiresAt", session.deadlines().idleExpiresAt().toString(),
                            "absoluteExpiresAt", session.deadlines().absoluteExpiresAt().toString()),
                    "security", Map.of("deviceTrusted", true,
                            "deviceBindingId", facts.bindingId().toString(),
                            "biometricLoginEnabled", facts.biometricLoginEnabled(),
                            "assurance", Map.of("devicePossession", "MFA_KEY_POSSESSION",
                                    "platformEvidence", facts.platformAssurance(),
                                    "biometricEnforcement", "NOT_APPLICABLE")));
            return ResponseEntity.ok().cacheControl(CacheControl.noStore())
                    .header("DPoP-Nonce", session.dpopNonce()).body(body);
        }
        if (result instanceof PasswordAuthenticationResult.Rejected) {
            return problem(HttpStatus.UNAUTHORIZED, "REQUEST_REJECTED");
        }
        if (result instanceof PasswordAuthenticationResult.Conflict) {
            return problem(HttpStatus.CONFLICT, "STATE_CONFLICT");
        }
        if (result instanceof PasswordAuthenticationResult.Processing) {
            return ResponseEntity.status(HttpStatus.ACCEPTED).cacheControl(CacheControl.noStore())
                    .body(Map.of("status", "PROCESSING", "operationId", operationId.toString(),
                            "nextAction", "POLL_RESULT", "correlationId", UUID.randomUUID().toString()));
        }
        return problem(HttpStatus.SERVICE_UNAVAILABLE, "TEMPORARILY_UNAVAILABLE");
    }

    private ResponseEntity<?> problem(HttpStatus status, String code) {
        return ResponseEntity.status(status).cacheControl(CacheControl.noStore())
                .body(Map.of("code", code, "message", "The request was rejected",
                        "correlationId", UUID.randomUUID().toString(),
                        "nextAction", "RETRY_LATER"));
    }
}
