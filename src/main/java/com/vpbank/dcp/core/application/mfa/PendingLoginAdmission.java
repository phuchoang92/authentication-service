package com.vpbank.dcp.core.application.mfa;

import com.vpbank.dcp.core.port.out.pending.PendingMfaLogin;

public sealed interface PendingLoginAdmission {
    record Admitted(PendingMfaLogin pending) implements PendingLoginAdmission { }
    record Rejected() implements PendingLoginAdmission { }
    record Unavailable() implements PendingLoginAdmission { }
}
