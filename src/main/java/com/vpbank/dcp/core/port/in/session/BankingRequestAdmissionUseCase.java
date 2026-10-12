package com.vpbank.dcp.core.port.in.session;

public interface BankingRequestAdmissionUseCase {
    BankingRequestAdmissionResult admit(BankingRequestAdmissionCommand command);
}
