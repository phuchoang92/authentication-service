package com.vpbank.dcp.auth.application.result;

import com.vpbank.dcp.auth.domain.enums.SessionStatus;
import com.vpbank.dcp.auth.domain.model.CustomerId;
import java.time.Instant;
import lombok.NonNull;

/** Business outcomes of {@link LoginUseCase}; infrastructure failures become {@link Unavailable}. */
public sealed interface LoginResult {

    /** A session exists; the token is inside {@code tokenEnvelope} (compact JWE to the app's key), never in clear. */
    record Authenticated(@NonNull String tokenEnvelope,
                         @NonNull CustomerId customerId,
                         @NonNull SessionStatus status,
                         @NonNull Instant idleExpiresAt,
                         @NonNull Instant absoluteExpiresAt) implements LoginResult {
        @Override
        public String toString() {
            return "Authenticated[customerId=" + customerId + ", status=" + status + ", redacted]";
        }
    }

    /**
     * Unknown user or wrong password: the same status and code for both. A known customer whose failures reached
     * the CAPTCHA threshold also gets {@code nextChallenge}, the challenge the next login answers, so the app can
     * show it at once; an unknown user never gets one (decided 2026-11-09), nor does a customer whose challenge
     * could not be stored. Null otherwise.
     */
    record InvalidCredentials(CaptchaChallenge nextChallenge) implements LoginResult {
        public static InvalidCredentials withoutChallenge() {
            return new InvalidCredentials(null);
        }
    }

    /** The identity exists but is not ACTIVE in Auth. */
    record AccountNotReady() implements LoginResult { }

    /** Too many failures: temporarily or permanently locked. The password was not sent to Keycloak. */
    record AccountLocked() implements LoginResult { }

    /** The identity has failed too often: this login was not tried, here is the challenge the next one answers. */
    record CaptchaRequired(@NonNull CaptchaChallenge challenge) implements LoginResult { }

    /** Keycloak, the database or the session store did not answer; nothing was issued. */
    record Unavailable() implements LoginResult { }
}
