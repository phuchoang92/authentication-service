package com.vpbank.dcp.auth.application.port.in;

import com.vpbank.dcp.auth.application.command.IssueServiceTokenCommand;
import com.vpbank.dcp.auth.application.result.IssueServiceTokenResult;

/** Internal service → Auth: a short-lived scoped JWT for a flow that has no customer login (slice 12). */
public interface IssueServiceTokenUseCase {
    IssueServiceTokenResult issue(IssueServiceTokenCommand command);
}
