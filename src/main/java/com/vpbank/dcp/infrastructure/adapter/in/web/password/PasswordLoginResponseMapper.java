package com.vpbank.dcp.infrastructure.adapter.in.web.password;

import com.vpbank.dcp.core.port.in.password.PasswordLoginResult;
import com.vpbank.dcp.core.port.out.session.PreparedSession;
import com.vpbank.dcp.core.port.out.session.SessionActivationSnapshot;
import com.vpbank.dcp.infrastructure.adapter.in.web.password.dto.PasswordLoginActiveResponse;
import com.vpbank.dcp.infrastructure.adapter.in.web.password.dto.PasswordLoginErrorResponse;
import com.vpbank.dcp.infrastructure.adapter.in.web.password.dto.PasswordLoginResponse;
import com.vpbank.dcp.infrastructure.adapter.in.web.password.dto.PasswordTotpRequiredResponse;
import com.vpbank.dcp.infrastructure.id.OpaqueBindingIdCodec;
import java.time.Clock;
import java.time.Duration;
import java.util.UUID;

import org.jspecify.annotations.NonNull;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

/** Only encrypted App delivery fields leave the private Auth endpoint. */
public final class PasswordLoginResponseMapper {
    private final Clock clock;
    private final OpaqueBindingIdCodec bindingIds = new OpaqueBindingIdCodec();

    public PasswordLoginResponseMapper(Clock clock) {
        this.clock = clock;
    }

    public ResponseEntity<PasswordLoginResponse> map(UUID operationId, PasswordLoginResult result) {
        if (result instanceof PasswordLoginResult.Active(PreparedSession session)) {
            if (!clock.instant().isBefore(session.deadlines().idleExpiresAt())) {
                return problem(HttpStatus.SERVICE_UNAVAILABLE, "TEMPORARILY_UNAVAILABLE");
            }
            long seconds = Math.max(1, Duration.between(clock.instant(),
                    session.deadlines().absoluteExpiresAt()).toSeconds());
            PasswordLoginResponse body = getLoginResponse(session, seconds);
            return ResponseEntity.ok().cacheControl(CacheControl.noStore())
                    .header("DPoP-Nonce", session.delivery().dpopNonce()).body(body);
        }
        if (result instanceof PasswordLoginResult.TotpRequired pending) {
            if (!clock.instant().isBefore(pending.expiresAt())) {
                return problem(HttpStatus.SERVICE_UNAVAILABLE, "TEMPORARILY_UNAVAILABLE");
            }
            var body = new PasswordTotpRequiredResponse("MFA_REQUIRED", pending.authenticationId(),
                    new PasswordTotpRequiredResponse.Challenge(pending.challengeId(), "TOTP",
                            pending.expiresAt()), pending.token().tokenEnvelope(),
                    pending.token().receipt(), "authentication:mfa");
            return ResponseEntity.status(HttpStatus.ACCEPTED).cacheControl(CacheControl.noStore()).body(body);
        }
        if (result instanceof PasswordLoginResult.Rejected) {
            return problem(HttpStatus.UNAUTHORIZED, "REQUEST_REJECTED");
        }
        if (result instanceof PasswordLoginResult.Conflict) {
            return problem(HttpStatus.CONFLICT, "STATE_CONFLICT");
        }
        return problem(HttpStatus.SERVICE_UNAVAILABLE, "TEMPORARILY_UNAVAILABLE");
    }

    private @NonNull PasswordLoginResponse getLoginResponse(PreparedSession session, long seconds) {
        SessionActivationSnapshot snapshot = session.snapshot();
        return new PasswordLoginActiveResponse("ACTIVE",
                session.delivery().tokenEnvelope(), session.delivery().receipt(), Math.min(seconds, 3600), "banking",
                new PasswordLoginActiveResponse.Session(session.deadlines().idleExpiresAt(),
                        session.deadlines().absoluteExpiresAt()),
                new PasswordLoginActiveResponse.Security(true, bindingIds.encode(snapshot.context().bindingId()),
                        snapshot.biometricLoginEnabled(), new PasswordLoginActiveResponse.Assurance(
                        snapshot.assurance().devicePossession().code(), snapshot.assurance().platformEvidence().code(),
                        snapshot.assurance().biometricEnforcement().code())));
    }

    private ResponseEntity<PasswordLoginResponse> problem(HttpStatus status, String code) {
        String message = status == HttpStatus.SERVICE_UNAVAILABLE
                ? "Sign-in could not be completed. Please sign in again."
                : "The request was rejected";
        return ResponseEntity.status(status).cacheControl(CacheControl.noStore())
                .body(new PasswordLoginErrorResponse(code, message,
                        UUID.randomUUID(), "START_NEW_LOGIN"));
    }
}
