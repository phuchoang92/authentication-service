package com.vpbank.dcp.auth.domain.model;

/** ACTIVE sessions admit requests; ENDED ones never come back (a new login is needed). */
public enum SessionStatus {
    ACTIVE,
    ENDED
}
