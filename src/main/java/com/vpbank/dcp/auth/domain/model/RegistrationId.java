package com.vpbank.dcp.auth.domain.model;

import java.util.Objects;
import java.util.UUID;

/** Identifier of one registration request; also the SMS message ID sent to Notification. */
public record RegistrationId(UUID value) {
    public RegistrationId {
        Objects.requireNonNull(value, "value");
    }

    public static RegistrationId random() {
        return new RegistrationId(UUID.randomUUID());
    }

    @Override
    public String toString() {
        return value.toString();
    }
}
