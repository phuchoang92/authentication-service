package com.vpbank.dcp.auth.domain.enums;

import java.util.Arrays;
import java.util.Optional;

/**
 * What a service token lets the BFF forward (slice 12). The BFF reads the token's {@code scope} claim and
 * forwards only the routes of that scope. The enum name is the Java vocabulary; {@link #code()} is the wire
 * value in the JWT and the request body, frozen by {@code ServiceScopeTest}. An unknown code is not a scope.
 */
public enum ServiceScope {
    /** Customer onboarding before any login exists: the token stands in for the session of one onboarding journey. */
    ONBOARDING("onboarding", true);

    private final String code;
    private final boolean businessReferenceRequired;

    ServiceScope(String code, boolean businessReferenceRequired) {
        this.code = code;
        this.businessReferenceRequired = businessReferenceRequired;
    }

    /** The value carried in the {@code scope} claim. */
    public String code() {
        return code;
    }

    /** Whether a token of this scope must name the business journey it belongs to (the onboarding request). */
    public boolean businessReferenceRequired() {
        return businessReferenceRequired;
    }

    /** Fail-closed: no normalisation, no default. */
    public static Optional<ServiceScope> fromCode(String code) {
        return Arrays.stream(values())
                .filter(scope -> scope.code.equals(code))
                .findFirst();
    }
}
