package com.vpbank.dcp.core.port.in.session;

public interface ActivateSessionUseCase {
    SessionActivationResult activate(ActivateSessionCommand command);
}
