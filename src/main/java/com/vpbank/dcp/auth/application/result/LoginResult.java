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

    /** Unknown user or wrong password: one answer for both, so nothing reveals account existence. */
    record InvalidCredentials() implements LoginResult { }

    /** The identity exists but is not ACTIVE in Auth. */
    record AccountNotReady() implements LoginResult { }

    /** Too many failures: temporarily or permanently locked. The password was not sent to Keycloak. */
    record AccountLocked() implements LoginResult { }

    /** Two or more failures: this attempt needs a solved CAPTCHA bound to the customer first. */
    record CaptchaRequired() implements LoginResult { }

    /** Keycloak, the database or the session store did not answer; nothing was issued. */
    record Unavailable() implements LoginResult { }
}
