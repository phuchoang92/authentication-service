package com.vpbank.dcp.auth.application.port.in;

import com.vpbank.dcp.auth.application.command.ConfirmEnrollmentCommand;
import com.vpbank.dcp.auth.application.result.ConfirmEnrollmentResult;

/** App → Auth with a restricted session: step "confirm" of device trust (DD 20 §4). */
public interface ConfirmEnrollmentUseCase {
    ConfirmEnrollmentResult confirm(ConfirmEnrollmentCommand command);
}
