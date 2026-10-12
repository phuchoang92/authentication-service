package com.vpbank.dcp.infrastructure.config;

import com.vpbank.dcp.core.port.out.authority.AuthorityControl;
import com.vpbank.dcp.core.port.out.authority.GenerationInstaller;
import com.vpbank.dcp.core.port.out.guard.SubjectBlockStore;
import com.vpbank.dcp.core.port.out.password.PasswordProofReplay;
import com.vpbank.dcp.core.port.out.replay.ReplayProtection;
import com.vpbank.dcp.infrastructure.adapter.out.redis.AuthorityRedisPreflight;
import com.vpbank.dcp.infrastructure.adapter.out.redis.RedisAuthorityControl;
import com.vpbank.dcp.infrastructure.adapter.out.redis.RedisGenerationInstaller;
import com.vpbank.dcp.infrastructure.adapter.out.redis.RedisPasswordProofReplay;
import com.vpbank.dcp.infrastructure.adapter.out.redis.RedisReplayProtection;
import com.vpbank.dcp.infrastructure.adapter.out.redis.RedisServerIdentity;
import com.vpbank.dcp.infrastructure.adapter.out.redis.RedisSubjectBlockStore;
import com.vpbank.dcp.infrastructure.adapter.out.redis.VerifiedAuthorityScript;
import com.vpbank.dcp.infrastructure.adapter.out.redis.key.AuthorityScope;
import com.vpbank.dcp.infrastructure.adapter.out.redis.key.GenerationKeys;
import com.vpbank.dcp.infrastructure.adapter.out.redis.key.GuardKeys;
import com.vpbank.dcp.infrastructure.adapter.out.redis.key.PasswordProofReplayKeys;
import com.vpbank.dcp.infrastructure.adapter.out.redis.key.ReplayKeys;
import com.vpbank.dcp.infrastructure.config.properties.AuthorityProperties;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;

@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(AuthorityProperties.class)
public class AuthorityConfiguration {

    private static final String REPLAY_SCRIPT_SHA256 =
            "ad0c9e765269fe2f451b3520e662b3a9d83b3746ecb3157b4cd941f207d7c335";
    private static final String PASSWORD_REPLAY_SHA256 =
            "1a8ab1738ea33ee578f64a6c0c1d009fa3d6a00cfe79d9bb7624fb157eada77a";
    private static final String SUBJECT_BLOCK_SHA256 =
            "0874127dccef414f2456cbfb11ff3034d6b4127769d91e807a47dd90f0e7fff1";
    private static final String CLOSE_CONTROL_SHA256 =
            "38ac6c49c6f9394efb54ab502c5f131c800c4c361cb9484f7f584c3a0b062af4";
    private static final String INSTALL_CLOSED_SHA256 =
            "e784f0e373bfd6e45b828902e9f539ce45b48fba8995164a0d52ed1c9dd4a424";

    @Bean
    AuthorityScope authorityScope(AuthorityProperties properties) {
        return new AuthorityScope(properties.scope());
    }

    @Bean
    ReplayProtection replayProtection(StringRedisTemplate redis, AuthorityScope scope) {
        DefaultRedisScript<String> script = VerifiedAuthorityScript.load(
                "redis/replay_reserve.lua", REPLAY_SCRIPT_SHA256);
        return new RedisReplayProtection(
                redis, new ReplayKeys(scope), new GenerationKeys(scope), script);
    }

    @Bean
    PasswordProofReplay passwordProofReplay(StringRedisTemplate redis, AuthorityScope scope) {
        return new RedisPasswordProofReplay(redis, new GenerationKeys(scope),
                new ReplayKeys(scope), new PasswordProofReplayKeys(scope),
                VerifiedAuthorityScript.load("redis/password_proof_reserve.lua",
                        PASSWORD_REPLAY_SHA256));
    }

    @Bean
    RedisServerIdentity redisServerIdentity(StringRedisTemplate redis) {
        return new RedisServerIdentity(redis);
    }

    @Bean
    SubjectBlockStore subjectBlockStore(StringRedisTemplate redis,
                                        RedisServerIdentity identity,
                                        AuthorityScope scope) {
        return new RedisSubjectBlockStore(redis,
                identity,
                new GuardKeys(scope),
                new GenerationKeys(scope),
                VerifiedAuthorityScript.load("redis/subject_block.lua", SUBJECT_BLOCK_SHA256));
    }

    @Bean
    AuthorityControl authorityControl(StringRedisTemplate redis,
                                      RedisServerIdentity identity,
                                      AuthorityScope scope) {
        return new RedisAuthorityControl(
                redis,
                identity,
                new GenerationKeys(scope),
                VerifiedAuthorityScript.load("redis/close_control.lua", CLOSE_CONTROL_SHA256));
    }

    @Bean
    GenerationInstaller generationInstaller(StringRedisTemplate redis,
                                            RedisServerIdentity identity,
                                            AuthorityScope scope) {
        return new RedisGenerationInstaller(redis,
                identity,
                new GenerationKeys(scope),
                VerifiedAuthorityScript.load("redis/install_closed_generation.lua", INSTALL_CLOSED_SHA256));
    }

    @Bean(initMethod = "verify")
    @ConditionalOnWebApplication
    AuthorityRedisPreflight authorityRedisPreflight(StringRedisTemplate redis) {
        return new AuthorityRedisPreflight(redis);
    }
}
