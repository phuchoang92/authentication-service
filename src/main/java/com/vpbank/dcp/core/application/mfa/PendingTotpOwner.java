package com.vpbank.dcp.core.application.mfa;

import com.vpbank.dcp.core.domain.customer.CustomerAuthenticationState;
import com.vpbank.dcp.core.port.out.device.LoginDeviceSnapshot;

public sealed interface PendingTotpOwner {
    record Current(CustomerAuthenticationState customer, LoginDeviceSnapshot device)
            implements PendingTotpOwner { }
    record Rejected() implements PendingTotpOwner { }
    record Unavailable() implements PendingTotpOwner { }
}
