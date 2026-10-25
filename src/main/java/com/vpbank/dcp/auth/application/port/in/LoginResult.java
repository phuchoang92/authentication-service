package com.vpbank.dcp.auth.application.port.in;

import com.vpbank.dcp.auth.domain.model.CustomerId;
import com.vpbank.dcp.auth.domain.model.SessionStatus;

import java.time.Instant;
import java.util.Objects;

/** Business outcomes of {@link LoginUseCase}; infrastructure failures become {@link Unavailable}. */
public sealed interface LoginResult {

    /** A session exists; the token is inside {@code tokenEnvelope} (compact JWE to the app's key), never in clear. */
    record Authenticated(String tokenEnvelope, CustomerId customerId, SessionStatus status,
                         Instant idleExpiresAt, Instant absoluteExpiresAt) implements LoginResult {
        public Authenticated {
            Objects.requireNonNull(tokenEnvelope, "tokenEnvelope");
            Objects.requireNonNull(customerId, "customerId");
            Objects.requireNonNull(status, "status");
            Objects.requireNonNull(idleExpiresAt, "idleExpiresAt");
            Objects.requireNonNull(absoluteExpiresAt, "absoluteExpiresAt");
        }

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
