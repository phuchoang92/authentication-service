package com.vpbank.dcp.infrastructure.config;

import com.vpbank.dcp.core.password.PasswordProofReplay;
import com.vpbank.dcp.core.replay.ReplayProtection;
import com.vpbank.dcp.infrastructure.adapter.out.redis.AuthorityRedisPreflight;
import com.vpbank.dcp.infrastructure.adapter.out.redis.RedisPasswordProofReplay;
import com.vpbank.dcp.infrastructure.adapter.out.redis.RedisReplayProtection;
import com.vpbank.dcp.infrastructure.adapter.out.redis.RedisServerIdentity;
import com.vpbank.dcp.infrastructure.adapter.out.redis.key.AuthorityScope;
import com.vpbank.dcp.infrastructure.adapter.out.redis.key.PasswordProofReplayKeys;
import com.vpbank.dcp.infrastructure.adapter.out.redis.key.ReplayKeys;
import com.vpbank.dcp.infrastructure.adapter.out.redis.key.RuntimeKeys;
import com.vpbank.dcp.infrastructure.config.properties.AuthorityProperties;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.core.StringRedisTemplate;

@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(AuthorityProperties.class)
public class AuthorityConfiguration {

    @Bean
    AuthorityScope authorityScope(AuthorityProperties properties) {
        return new AuthorityScope(properties.scope());
    }

    @Bean
    RedisServerIdentity redisServerIdentity(StringRedisTemplate redis, AuthorityScope scope) {
        return new RedisServerIdentity(redis, new RuntimeKeys(scope));
    }

    @Bean
    ReplayProtection replayProtection(StringRedisTemplate redis, RedisServerIdentity identity,
                                      AuthorityScope scope) {
        return new RedisReplayProtection(redis, identity, new ReplayKeys(scope));
    }

    @Bean
    PasswordProofReplay passwordProofReplay(StringRedisTemplate redis,
                                            RedisServerIdentity identity, AuthorityScope scope) {
        return new RedisPasswordProofReplay(redis, identity,
                new ReplayKeys(scope), new PasswordProofReplayKeys(scope));
    }

    @Bean(initMethod = "verify")
    @ConditionalOnWebApplication
    AuthorityRedisPreflight authorityRedisPreflight(StringRedisTemplate redis,
                                                   RedisServerIdentity identity) {
        return new AuthorityRedisPreflight(redis, identity);
    }
}
