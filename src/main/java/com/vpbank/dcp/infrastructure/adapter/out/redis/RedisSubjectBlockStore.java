package com.vpbank.dcp.infrastructure.adapter.out.redis;

import com.vpbank.dcp.core.port.out.guard.SubjectBlock;
import com.vpbank.dcp.core.port.out.guard.SubjectBlockResult;
import com.vpbank.dcp.core.port.out.guard.SubjectBlockStore;
import com.vpbank.dcp.core.port.out.guard.SubjectGuardUnavailableException;
import com.vpbank.dcp.infrastructure.adapter.out.redis.key.GenerationKeys;
import com.vpbank.dcp.infrastructure.adapter.out.redis.key.GuardKeys;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;

import java.util.List;
import java.util.Objects;

/**
 * Only applies monotonic Customer blocking; no script clears other deny causes.
 */
public final class RedisSubjectBlockStore implements SubjectBlockStore {

    private final StringRedisTemplate redis;
    private final RedisServerIdentity identity;
    private final GuardKeys guardKeys;
    private final GenerationKeys generationKeys;
    private final DefaultRedisScript<String> script;

    public RedisSubjectBlockStore(StringRedisTemplate redis, RedisServerIdentity identity,
                                  GuardKeys guardKeys, GenerationKeys generationKeys,
                                  DefaultRedisScript<String> script) {
        this.redis = Objects.requireNonNull(redis, "redis");
        this.identity = Objects.requireNonNull(identity, "identity");
        this.guardKeys = Objects.requireNonNull(guardKeys, "guardKeys");
        this.generationKeys = Objects.requireNonNull(generationKeys, "generationKeys");
        this.script = Objects.requireNonNull(script, "script");
    }

    @Override
    public SubjectBlockResult apply(SubjectBlock block) {
        Objects.requireNonNull(block, "block");
        try {
            String runId = identity.currentRunId();
            if (runId == null || runId.isBlank()) {
                return SubjectBlockResult.AUTHORITY_CLOSED;
            }
            String outcome = redis.execute(script,
                    List.of(generationKeys.control(), guardKeys.forSubject(block.subjectId())),
                    block.generation().toString(), runId, block.subjectId().toString(),
                    Long.toString(block.guardVersion()),
                    Long.toString(block.customerSecurityVersion()),
                    Long.toString(block.credentialSecurityVersion()));
            return switch (outcome) {
                case "APPLIED" -> SubjectBlockResult.APPLIED;
                case "ALREADY_APPLIED" -> SubjectBlockResult.ALREADY_APPLIED;
                case "STALE" -> SubjectBlockResult.STALE;
                default -> SubjectBlockResult.AUTHORITY_CLOSED;
            };
        } catch (RuntimeException failure) {
            throw new SubjectGuardUnavailableException(failure);
        }
    }
}
