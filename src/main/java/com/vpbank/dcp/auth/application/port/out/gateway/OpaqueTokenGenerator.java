package com.vpbank.dcp.auth.application.port.out.gateway;

import com.vpbank.dcp.auth.domain.model.OpaqueToken;

/** 32 random bytes under the current lookup key version. Randomness is a boundary, so it is a port. */
public interface OpaqueTokenGenerator {
    OpaqueToken next();
}
