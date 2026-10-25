package com.vpbank.dcp.auth.application.port.in;

import com.vpbank.dcp.auth.application.result.DeviceSummary;
import com.vpbank.dcp.auth.domain.enums.Channel;
import com.vpbank.dcp.auth.domain.model.CustomerId;
import java.util.List;

/** App → Auth (ACTIVE session): the customer's devices on the channel. */
public interface ListDevicesUseCase {
    List<DeviceSummary> list(CustomerId customerId, Channel channel);
}
