package com.vpbank.dcp.infrastructure.adapter.in.web.password;

import com.vpbank.dcp.core.port.in.password.PasswordLoginResult;
import com.vpbank.dcp.core.port.out.session.PreparedSession;
import com.vpbank.dcp.core.port.out.session.SessionActivationSnapshot;
import com.vpbank.dcp.infrastructure.adapter.in.web.password.dto.PasswordLoginActiveResponse;
import com.vpbank.dcp.infrastructure.adapter.in.web.password.dto.PasswordLoginErrorResponse;
import com.vpbank.dcp.infrastructure.adapter.in.web.password.dto.PasswordLoginResponse;
import com.vpbank.dcp.infrastructure.adapter.in.web.password.dto.PasswordNeedTrustedDeviceResponse;
import com.vpbank.dcp.infrastructure.id.OpaqueBindingIdCodec;
import java.time.Clock;
import java.time.Duration;

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

    public ResponseEntity<PasswordLoginResponse> map(PasswordLoginResult result) {
        if (result instanceof PasswordLoginResult.Active(PreparedSession session)) {
            return active(session);
        }
        if (result instanceof PasswordLoginResult.NeedTrustedDevice restricted) {
            if (!clock.instant().isBefore(restricted.expiresAt())) {
                return problem(HttpStatus.SERVICE_UNAVAILABLE, "TEMPORARILY_UNAVAILABLE");
            }
            long seconds = Math.max(1, Duration.between(clock.instant(),
                    restricted.expiresAt()).toSeconds());
            // No DPoP-Nonce: the trusted-device API is called with the BFF's JWT, not DPoP.
            return ResponseEntity.ok().cacheControl(CacheControl.noStore())
                    .body(new PasswordNeedTrustedDeviceResponse("NEED_TRUSTED_DEVICE",
                            restricted.tokenEnvelope(), restricted.receipt(), seconds));
        }
        if (result instanceof PasswordLoginResult.Rejected) {
            return problem(HttpStatus.UNAUTHORIZED, "REQUEST_REJECTED");
        }
        if (result instanceof PasswordLoginResult.Conflict) {
            return problem(HttpStatus.CONFLICT, "STATE_CONFLICT");
        }
        return problem(HttpStatus.SERVICE_UNAVAILABLE, "TEMPORARILY_UNAVAILABLE");
    }

    /** The ACTIVE body, shared by password login and a confirmed trusted device. */
    public ResponseEntity<PasswordLoginResponse> active(PreparedSession session) {
        if (!clock.instant().isBefore(session.deadlines().idleExpiresAt())) {
            return problem(HttpStatus.SERVICE_UNAVAILABLE, "TEMPORARILY_UNAVAILABLE");
        }
        long seconds = Math.max(1, Duration.between(clock.instant(),
                session.deadlines().absoluteExpiresAt()).toSeconds());
        PasswordLoginResponse body = getLoginResponse(session, seconds);
        return ResponseEntity.ok().cacheControl(CacheControl.noStore())
                .header("DPoP-Nonce", session.delivery().dpopNonce()).body(body);
    }

    private @NonNull PasswordLoginResponse getLoginResponse(PreparedSession session, long seconds) {
        SessionActivationSnapshot snapshot = session.snapshot();
        return new PasswordLoginActiveResponse("ACTIVE",
                session.delivery().tokenEnvelope(), session.delivery().receipt(), Math.min(seconds, 3600), "banking",
                new PasswordLoginActiveResponse.Session(session.deadlines().idleExpiresAt(),
                        session.deadlines().absoluteExpiresAt()),
                new PasswordLoginActiveResponse.Security(true, bindingIds.encode(snapshot.context().bindingId().value()),
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
                        java.util.UUID.randomUUID(), "START_NEW_LOGIN"));
    }
}
