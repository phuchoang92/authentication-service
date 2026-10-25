package com.vpbank.dcp.auth.application.port.in;

import com.vpbank.dcp.auth.application.command.InitEnrollmentCommand;
import com.vpbank.dcp.auth.application.result.InitEnrollmentResult;

/** App → Auth with a restricted session: step "init" of device trust (DD 20 §4). */
public interface InitEnrollmentUseCase {
    InitEnrollmentResult init(InitEnrollmentCommand command);
}
