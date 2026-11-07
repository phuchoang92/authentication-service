package com.vpbank.dcp.auth.application.command;

import com.vpbank.dcp.auth.domain.enums.Channel;
import com.vpbank.dcp.auth.domain.model.CustomerId;
import com.vpbank.dcp.auth.domain.model.DeviceId;
import lombok.Builder;
import lombok.NonNull;

/**
 * What the device routing needs after a correct password: whose login, on which channel and installation.
 * {@code deviceId} is null on WEB, which has no device trust; a MOBILE login always names its installation
 * ({@link LoginCommand}). {@code correlationId} ties the audit trail to the session about to be issued.
 */
@Builder
public record RouteAfterPasswordCommand(@NonNull CustomerId customerId,
                                        @NonNull Channel channel,
                                        DeviceId deviceId,
                                        @NonNull String correlationId) {
    public RouteAfterPasswordCommand {
        if (channel == Channel.MOBILE && deviceId == null) {
            throw new IllegalArgumentException("A mobile login names its installation");
        }
    }
}
