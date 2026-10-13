package com.vpbank.dcp.core.application.mfa;

import com.vpbank.dcp.core.port.out.pending.PendingTotpLogin;

public sealed interface PendingTotpAdmission {
    record Admitted(PendingTotpLogin pending) implements PendingTotpAdmission { }
    record Rejected() implements PendingTotpAdmission { }
    record Unavailable() implements PendingTotpAdmission { }
}
