package com.vpbank.dcp.core.port.out.session;

import com.vpbank.dcp.core.domain.session.SessionDeadlines;

public sealed interface SessionAdmissionResult {
    record Admitted(SessionDeadlines deadlines) implements SessionAdmissionResult { }
    record NonceRequired(String nonce) implements SessionAdmissionResult { }
    record Denied() implements SessionAdmissionResult { }
    record AuthorityClosed() implements SessionAdmissionResult { }
}
