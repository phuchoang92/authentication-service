package com.vpbank.dcp.auth.application.port.in;

import com.vpbank.dcp.auth.application.command.RequestApprovalCommand;
import com.vpbank.dcp.auth.application.result.RequestApprovalResult;

/** Slice 6, approval of a new device by the current primary device (DD 20 §4, phase 4). */
public interface RequestApprovalUseCase {
    RequestApprovalResult request(RequestApprovalCommand command);
}
