package com.vpbank.dcp.core.port.out.guard;

import java.util.Objects;
import java.util.UUID;

/**
 * A durable, monotonic subject block prepared before online authority is changed.
 */
public record SubjectBlock(UUID subjectId, UUID generation, long guardVersion,
                           long customerSecurityVersion, long credentialSecurityVersion) {

    public SubjectBlock {
        Objects.requireNonNull(subjectId, "subjectId");
        Objects.requireNonNull(generation, "generation");
        if (guardVersion < 1 || customerSecurityVersion < 0 || credentialSecurityVersion < 0
                || guardVersion > 9007199254740991L
                || customerSecurityVersion > 9007199254740991L
                || credentialSecurityVersion > 9007199254740991L) {
            throw new InvalidSubjectBlockException();
        }
    }
}
