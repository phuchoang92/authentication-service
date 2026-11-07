package com.vpbank.dcp.auth.application.result;

import com.vpbank.dcp.auth.domain.enums.ServiceScope;
import java.time.Instant;
import lombok.NonNull;

public sealed interface IssueServiceTokenResult {
    /** The signed compact JWS and what the caller needs to know about it. {@code toString} hides the token. */
    record Issued(@NonNull String token,
                  @NonNull ServiceScope scope,
                  @NonNull Instant expiresAt) implements IssueServiceTokenResult {
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
