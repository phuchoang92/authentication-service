package com.vpbank.dcp.infrastructure.adapter.in.web.trusteddevice;

import com.vpbank.dcp.core.trusteddevice.ConfirmTrustedDeviceResult;
import com.vpbank.dcp.core.trusteddevice.InitTrustedDeviceResult;
import com.vpbank.dcp.core.trusteddevice.VerifyTrustedDeviceResult;
import com.vpbank.dcp.infrastructure.adapter.in.web.password.PasswordLoginResponseMapper;
import com.vpbank.dcp.infrastructure.adapter.in.web.trusteddevice.dto.TrustedDeviceErrorResponse;
import com.vpbank.dcp.infrastructure.adapter.in.web.trusteddevice.dto.TrustedDeviceInitResponse;
import com.vpbank.dcp.infrastructure.adapter.in.web.trusteddevice.dto.TrustedDeviceResponse;
import com.vpbank.dcp.infrastructure.adapter.in.web.trusteddevice.dto.TrustedDeviceVerifyResponse;
import java.util.Objects;
import java.util.UUID;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

/**
 * {@code nextAction} tells the App what to do: {@code RETRY} the same step,
 * {@code COMPLETE_MFA} at the MFA service then confirm again, {@code VISIT_BRANCH} when the
 * Customer has no usable factor, or {@code START_NEW_LOGIN}.
 */
public final class TrustedDeviceResponseMapper {
    private static final String REJECTED = "The request was rejected";
    private static final String UNAVAILABLE = "Please try again later";

    private final PasswordLoginResponseMapper sessions;

    public TrustedDeviceResponseMapper(PasswordLoginResponseMapper sessions) {
        this.sessions = Objects.requireNonNull(sessions);
    }

    public ResponseEntity<TrustedDeviceResponse> init(InitTrustedDeviceResult result) {
        return switch (result) {
            case InitTrustedDeviceResult.Started(var enrollmentId, var suite, var serverPublicKey,
                                                 var protectedChallenge) ->
                    ResponseEntity.ok().cacheControl(CacheControl.noStore())
                            .body(new TrustedDeviceInitResponse("KEY_EXCHANGE", enrollmentId, suite,
                                    serverPublicKey, protectedChallenge));
            case InitTrustedDeviceResult.Rejected() -> rejected();
            case InitTrustedDeviceResult.Unavailable() -> unavailable();
        };
    }

    public ResponseEntity<TrustedDeviceResponse> verify(VerifyTrustedDeviceResult result) {
        return switch (result) {
            case VerifyTrustedDeviceResult.MfaRequired(var mfaTransactionId) ->
                    ResponseEntity.ok().cacheControl(CacheControl.noStore())
                            .body(new TrustedDeviceVerifyResponse("MFA_REQUIRED", mfaTransactionId));
            case VerifyTrustedDeviceResult.WrongChallenge(var attemptsLeft) -> error(
                    HttpStatus.UNAUTHORIZED, "WRONG_CHALLENGE", REJECTED, "RETRY", attemptsLeft);
            case VerifyTrustedDeviceResult.NoUsableFactor() -> error(HttpStatus.FORBIDDEN,
                    "NO_USABLE_FACTOR", REJECTED, "VISIT_BRANCH", null);
            case VerifyTrustedDeviceResult.Rejected() -> rejected();
            case VerifyTrustedDeviceResult.Unavailable() -> unavailable();
        };
    }

    public ResponseEntity<?> confirm(ConfirmTrustedDeviceResult result) {
        return switch (result) {
            case ConfirmTrustedDeviceResult.Active(var session) -> sessions.active(session);
            case ConfirmTrustedDeviceResult.MfaPending() -> error(HttpStatus.CONFLICT,
                    "MFA_NOT_PASSED", REJECTED, "COMPLETE_MFA", null);
            case ConfirmTrustedDeviceResult.Expired() -> error(HttpStatus.UNAUTHORIZED,
                    "MFA_EXPIRED", REJECTED, "START_NEW_LOGIN", null);
            case ConfirmTrustedDeviceResult.Rejected() -> rejected();
            case ConfirmTrustedDeviceResult.Unavailable() -> unavailable();
        };
    }

    private static ResponseEntity<TrustedDeviceResponse> rejected() {
        return error(HttpStatus.UNAUTHORIZED, "REQUEST_REJECTED", REJECTED, "START_NEW_LOGIN", null);
    }

    /** The session is kept unless the step had already ended it; a retry then gets rejected. */
    private static ResponseEntity<TrustedDeviceResponse> unavailable() {
        return error(HttpStatus.SERVICE_UNAVAILABLE, "TEMPORARILY_UNAVAILABLE", UNAVAILABLE,
                "RETRY", null);
    }

    private static ResponseEntity<TrustedDeviceResponse> error(HttpStatus status, String code,
                                                               String message, String nextAction,
                                                               Integer attemptsLeft) {
        return ResponseEntity.status(status).cacheControl(CacheControl.noStore())
                .body(new TrustedDeviceErrorResponse(code, message, UUID.randomUUID(), nextAction,
                        attemptsLeft));
    }
}
