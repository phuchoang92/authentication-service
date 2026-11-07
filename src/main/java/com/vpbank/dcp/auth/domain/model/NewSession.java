package com.vpbank.dcp.auth.domain.model;

import com.vpbank.dcp.auth.domain.enums.Channel;
import java.time.Instant;
import lombok.Builder;
import lombok.NonNull;

/**
 * A session about to start: its ID, whose it is, on which channel and installation, and when it starts.
 * {@code deviceId} is null on WEB, which has no installation. Both kinds of session start from it
 * ({@link Session#start}, {@link Session#startRestricted}).
 */
@Builder
public record NewSession(@NonNull SessionId id,
                         @NonNull CustomerId customerId,
                         @NonNull Channel channel,
                         DeviceId deviceId,
                         @NonNull Instant startedAt) {
}
