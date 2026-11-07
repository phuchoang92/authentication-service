package com.vpbank.dcp.auth.domain.model;

import java.util.UUID;
import lombok.NonNull;

/** Identifier of one registration request; also the SMS message ID sent to Notification. */
public record RegistrationId(@NonNull UUID value) {

    public static RegistrationId random() {
        return new RegistrationId(UUID.randomUUID());
    }

    @Override
    public String toString() {
        return value.toString();
    }
}
