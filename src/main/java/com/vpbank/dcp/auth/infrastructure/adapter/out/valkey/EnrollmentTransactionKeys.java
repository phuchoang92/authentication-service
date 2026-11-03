package com.vpbank.dcp.auth.infrastructure.adapter.out.valkey;

import com.vpbank.dcp.auth.domain.enums.Channel;
import com.vpbank.dcp.auth.domain.model.CustomerId;
import com.vpbank.dcp.auth.domain.model.DeviceId;
import java.util.Objects;

/**
 * Key factory for primary enrollments in flight (slice 11): {@code enrollment-tx:v1:<channel>:<customerId>:<deviceId>}.
 * Customer and device IDs are business identifiers whose formats exclude {@code :}; the key needs no key material.
 * No I/O, no clock, no TTL decisions here.
 */
public final class EnrollmentTransactionKeys {
    static final String PREFIX = "enrollment-tx:v1:";

    public String forDevice(CustomerId customerId, Channel channel, DeviceId deviceId) {
        Objects.requireNonNull(customerId, "customerId");
        Objects.requireNonNull(channel, "channel");
        Objects.requireNonNull(deviceId, "deviceId");
        return PREFIX + channel.name() + ":" + customerId.value() + ":" + deviceId.value();
    }
}
