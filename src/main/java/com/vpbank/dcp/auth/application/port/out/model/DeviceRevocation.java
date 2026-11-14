package com.vpbank.dcp.auth.application.port.out.model;

import com.vpbank.dcp.auth.domain.enums.Channel;
import com.vpbank.dcp.auth.domain.model.CustomerId;
import com.vpbank.dcp.auth.domain.model.TrustedDeviceId;
import lombok.NonNull;

/** The exact binding selected by an authorized primary device for removal. */
public record DeviceRevocation(@NonNull CustomerId customerId,
                               @NonNull Channel channel,
                               @NonNull TrustedDeviceId targetBindingId,
                               @NonNull TrustedDeviceId primaryBindingId,
                               @NonNull String reasonCode,
                               @NonNull String correlationId) {
}
