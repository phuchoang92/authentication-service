package com.vpbank.dcp.infrastructure.adapter.out.persistence.repository.authority;

final class AuthorityLeaseSql {

    static final String CLOSE_WITH_NEW_FENCE = """
            UPDATE auth_authority_control
               SET generation = UNHEX(REPLACE(:generation, '-', '')),
                   redis_run_id = :redisRunId,
                   state = 'CLOSED',
                   controller_id = UNHEX(REPLACE(:controllerId, '-', '')),
                   lease_until = :leaseUntil,
                   fence = :nextFence,
                   version = version + 1,
                   updated_at = UTC_TIMESTAMP(6)
             WHERE bank_scope = :bankScope
               AND version = :expectedVersion
               AND fence = :expectedFence
               AND :nextFence > fence
               AND version < 9007199254740991
            """;

    private AuthorityLeaseSql() {
    }
}
