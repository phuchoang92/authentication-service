package com.vpbank.dcp.auth.domain.model;

import com.vpbank.dcp.auth.domain.enums.RegistrationState;
import com.vpbank.dcp.auth.domain.exception.RegistrationStateException;
import java.time.Instant;
import java.util.Objects;
import lombok.Builder;

/**
 * One registration request and its place in the flow
 * RESERVED → USER_CREATED → SMS_ACCEPTED → READY, or FAILED from any open step.
 *
 * <p>Every step returns a new instance with the same {@code version}: the version is the one the
 * repository must still see when it saves the step (compare-and-set). The Keycloak issuer and
 * subject are known from USER_CREATED on; before that they are null.
 */
@Builder(toBuilder = true)
public record Registration(RegistrationId id, CustomerId customerId, UserName userName,
                           RequestDigest requestDigest, RegistrationState state,
                           String identityIssuer, String identitySubject,
                           Instant expiresAt, long version) {
    public Registration {
        Objects.requireNonNull(id, "id");
        Objects.requireNonNull(customerId, "customerId");
        Objects.requireNonNull(userName, "userName");
        Objects.requireNonNull(requestDigest, "requestDigest");
        Objects.requireNonNull(state, "state");
        Objects.requireNonNull(expiresAt, "expiresAt");
        if ((identityIssuer == null) != (identitySubject == null)) {
            throw new IllegalArgumentException("Identity issuer and subject are set together");
        }
        if (state != RegistrationState.RESERVED && state != RegistrationState.FAILED && identitySubject == null) {
            throw new IllegalArgumentException(state + " needs the identity issuer and subject");
        }
    }

    /** A new request, not yet stored. */
    public static Registration reserve(RegistrationId id, CustomerId customerId, UserName userName,
                                       RequestDigest requestDigest, Instant expiresAt) {
        return Registration.builder()
                .id(id)
                .customerId(customerId)
                .userName(userName)
                .requestDigest(requestDigest)
                .state(RegistrationState.RESERVED)
                .expiresAt(expiresAt)
                .version(0)
                .build();
    }

    public Registration markUserCreated(String identityIssuer, String identitySubject) {
        requireState(RegistrationState.RESERVED);
        Objects.requireNonNull(identityIssuer, "identityIssuer");
        Objects.requireNonNull(identitySubject, "identitySubject");
        return toBuilder()
                .state(RegistrationState.USER_CREATED)
                .identityIssuer(identityIssuer)
                .identitySubject(identitySubject)
                .build();
    }

    public Registration markSmsAccepted() {
        requireState(RegistrationState.USER_CREATED);
        return toBuilder().state(RegistrationState.SMS_ACCEPTED).build();
    }

    public Registration complete() {
        requireState(RegistrationState.SMS_ACCEPTED);
        return toBuilder().state(RegistrationState.READY).build();
    }

    public Registration fail() {
        requireState(RegistrationState.RESERVED, RegistrationState.USER_CREATED, RegistrationState.SMS_ACCEPTED);
        return toBuilder().state(RegistrationState.FAILED).build();
    }

    /** The repository saw this version in the database: the next step builds on it. */
    public Registration withVersion(long storedVersion) {
        return toBuilder().version(storedVersion).build();
    }

    public boolean isSameRequest(RequestDigest digest) {
        return requestDigest.equals(digest);
    }

    public boolean isOpen() {
        return !state.finished();
    }

    private void requireState(RegistrationState... allowed) {
        for (RegistrationState candidate : allowed) {
            if (candidate == state) {
                return;
            }
        }
        throw new RegistrationStateException(state, allowed);
    }
}
