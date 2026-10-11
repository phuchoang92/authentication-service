package com.vpbank.dcp.core.port.out.password;

import java.util.Optional;
import java.util.UUID;

/** Reads current binding and Kdev state; no App-provided ID is trusted as ownership. */
public interface PasswordDeviceRouteStore {

    Optional<PasswordDeviceRouteEvidence> currentRoute(UUID operationId, UUID subjectId,
                                                        String appId);
}
