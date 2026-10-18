package com.vpbank.dcp.core.application.mfa;

import com.vpbank.dcp.core.domain.customer.CustomerAuthenticationState;
import com.vpbank.dcp.core.port.out.device.LoginDeviceSnapshot;

public sealed interface PendingLoginOwner {
    record Current(CustomerAuthenticationState customer, LoginDeviceSnapshot device)
            implements PendingLoginOwner { }
    record Rejected() implements PendingLoginOwner { }
    record Unavailable() implements PendingLoginOwner { }
}
