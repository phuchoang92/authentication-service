package com.vpbank.dcp.auth.application.port.in;

import com.vpbank.dcp.auth.application.command.AuthorizeEnrollmentCommand;
import com.vpbank.dcp.auth.application.result.AuthorizeEnrollmentResult;

/** Slice 6, approval of a new device by the current primary device (DD 20 §4, phase 4). */
public interface AuthorizeEnrollmentUseCase {
    AuthorizeEnrollmentResult authorize(AuthorizeEnrollmentCommand command);
}
