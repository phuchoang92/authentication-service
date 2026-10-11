package com.vpbank.dcp.core.port.out.authority;

import java.util.Objects;
import java.util.UUID;

public record ControlClosure(UUID generation, long controllerFence) {

    public ControlClosure {
        Objects.requireNonNull(generation, "generation");
        if (controllerFence < 0 || controllerFence > 9007199254740991L) {
            throw new InvalidAuthorityLeaseChangeException();
        }
    }
}
