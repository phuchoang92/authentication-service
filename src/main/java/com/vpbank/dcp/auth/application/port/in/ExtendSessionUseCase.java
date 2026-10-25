package com.vpbank.dcp.auth.application.port.in;

/** BFF → Auth (internal) after it admitted a request: slide the idle deadline (flow 16). */
public interface ExtendSessionUseCase {
    ExtendSessionResult extend(ExtendSessionCommand command);
}
