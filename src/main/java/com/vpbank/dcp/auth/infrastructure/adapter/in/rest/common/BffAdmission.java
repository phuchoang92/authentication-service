package com.vpbank.dcp.auth.infrastructure.adapter.in.rest.common;

import com.vpbank.dcp.auth.domain.model.AdmittedSession;
import java.util.Objects;

/**
 * What {@link BffAssertionFilter} leaves on the request for a trusted-device route: the session the BFF
 * admitted, already checked and typed. The controller hands it to the REST mapper unopened; the mapper puts
 * the {@link AdmittedSession} into the command.
 */
public record BffAdmission(AdmittedSession admittedSession) {
    public BffAdmission {
        Objects.requireNonNull(admittedSession, "admittedSession");
    }
}
