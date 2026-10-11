package com.vpbank.dcp.infrastructure.adapter.out.redis.codec;

import java.util.Objects;
import java.util.UUID;

public record SubjectGuardSnapshot(
        UUID subjectId, UUID generation, long guardVersion,
        SecurityFloor floor, DenyCauses causes) {

    public SubjectGuardSnapshot {
        Objects.requireNonNull(subjectId, "subjectId");
        Objects.requireNonNull(generation, "generation");
        Objects.requireNonNull(floor, "floor");
        Objects.requireNonNull(causes, "causes");
        AuthorityNumberCodec.encode(guardVersion);
    }
}
