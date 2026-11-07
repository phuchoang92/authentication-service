package com.vpbank.dcp.auth.domain.model;

import com.vpbank.dcp.auth.domain.enums.Channel;
import lombok.NonNull;

/**
 * One app installation of a customer on a channel: what a device row, a request and a session are about.
 */
public record DeviceInstallation(@NonNull CustomerId customerId, @NonNull Channel channel, @NonNull DeviceId deviceId) {
}
