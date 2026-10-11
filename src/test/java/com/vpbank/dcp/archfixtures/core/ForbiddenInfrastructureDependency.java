package com.vpbank.dcp.archfixtures.core;

import com.vpbank.dcp.infrastructure.adapter.out.redis.RedisServerIdentity;

/** Negative fixture; proves core cannot refer to infrastructure implementation types. */
public final class ForbiddenInfrastructureDependency {

    private RedisServerIdentity forbidden;
}
