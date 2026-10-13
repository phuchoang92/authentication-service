package com.vpbank.dcp.core.port.in.mfa;

import com.vpbank.dcp.core.port.out.session.PreparedSession;

public sealed interface TotpLoginResult {
    record Active(PreparedSession session) implements TotpLoginResult { }
    record Rejected() implements TotpLoginResult { }
    record Unavailable() implements TotpLoginResult { }
}
