package com.vpbank.dcp.core.port.in.mfa;

public interface CompleteTotpLoginUseCase {
    TotpLoginResult complete(TotpLoginCommand command);
}
