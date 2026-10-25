package com.vpbank.dcp.auth.application.port.in;

import com.vpbank.dcp.auth.application.command.VerifyEnrollmentCommand;
import com.vpbank.dcp.auth.application.result.VerifyEnrollmentResult;

/** App → Auth with a restricted session: step "verify" of device trust (DD 20 §4). */
public interface VerifyEnrollmentUseCase {
    VerifyEnrollmentResult verify(VerifyEnrollmentCommand command);
}
