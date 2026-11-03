package com.vpbank.dcp.auth.application.result;

import com.vpbank.dcp.auth.domain.enums.ServiceScope;
import java.time.Instant;
import java.util.Objects;

public sealed interface IssueServiceTokenResult {
    /** The signed compact JWS and what the caller needs to know about it. {@code toString} hides the token. */
    record Issued(String token, ServiceScope scope, Instant expiresAt) implements IssueServiceTokenResult {
        public Issued {
            Objects.requireNonNull(token, "token");
            Objects.requireNonNull(scope, "scope");
            Objects.requireNonNull(expiresAt, "expiresAt");
        }

        @Override
        public String toString() {
            return "Issued[token=redacted, scope=" + scope + ", expiresAt=" + expiresAt + "]";
        }
    }

    /** The caller is not granted that scope. */
    record ScopeNotAllowed() implements IssueServiceTokenResult { }

    /** The scope binds the token to a business journey and the request named none. */
    record BusinessReferenceRequired() implements IssueServiceTokenResult { }
}
