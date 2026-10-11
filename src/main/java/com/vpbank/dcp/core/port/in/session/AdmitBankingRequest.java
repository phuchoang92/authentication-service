package com.vpbank.dcp.core.port.in.session;

import com.vpbank.dcp.core.application.session.BankingAdmissionCommand;
import com.vpbank.dcp.core.application.session.BankingAdmissionDecision;

public interface AdmitBankingRequest {
    BankingAdmissionDecision admit(BankingAdmissionCommand command);
}
