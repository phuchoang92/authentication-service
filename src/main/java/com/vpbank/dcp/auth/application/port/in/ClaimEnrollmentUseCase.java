package com.vpbank.dcp.auth.application.port.in;

import com.vpbank.dcp.auth.application.command.ClaimEnrollmentCommand;
import com.vpbank.dcp.auth.application.result.ClaimEnrollmentResult;

/** Slice 6, approval of a new device by the current primary device (DD 20 §4, phase 4). */
public interface ClaimEnrollmentUseCase {
    ClaimEnrollmentResult claim(ClaimEnrollmentCommand command);
}
