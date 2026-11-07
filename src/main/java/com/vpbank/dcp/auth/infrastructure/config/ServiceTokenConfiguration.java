package com.vpbank.dcp.auth.infrastructure.config;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.vpbank.dcp.auth.application.port.in.IssueServiceTokenUseCase;
import com.vpbank.dcp.auth.application.port.out.gateway.ServiceTokenSigner;
import com.vpbank.dcp.auth.application.port.out.repository.SecurityAuditStore;
import com.vpbank.dcp.auth.application.service.IssueServiceTokenService;
import com.vpbank.dcp.auth.application.service.ServiceTokenSettings;
import com.vpbank.dcp.auth.domain.enums.ServiceScope;
import com.vpbank.dcp.auth.domain.model.ServiceId;
import com.vpbank.dcp.auth.domain.model.ServiceScopeGrants;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.common.AssertionReplayGuard;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.common.ErrorMessages;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.common.ServiceClientAssertionFilter;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.common.ServiceClientAssertionVerifier;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.common.ServiceTokenPublicKeys;
import com.vpbank.dcp.auth.infrastructure.adapter.in.rest.mapper.ServiceTokenRestMapper;
import com.vpbank.dcp.auth.infrastructure.adapter.out.jose.NimbusServiceTokenSigner;
import com.vpbank.dcp.auth.infrastructure.adapter.out.valkey.ServiceClientAssertionKeys;
import com.vpbank.dcp.auth.infrastructure.adapter.out.valkey.ValkeyAssertionReplayStore;
import java.text.ParseException;
import java.time.Clock;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.web.servlet.LocaleResolver;

/**
 * Scoped service tokens for flows without a customer session (slice 12), off by default. The whole object graph
 * of the capability is here: settings and grants from the properties, the signer and its public JWKS, the
 * client-assertion gate with its own replay store on Valkey, the use case and the REST mapper. A key that is not
 * what the setting promises, or a grant naming an unknown scope, stops startup naming the setting.
 */
@Configuration(proxyBeanMethods = false)
@ConditionalOnProperty(prefix = "auth.service-token", name = "enabled", havingValue = "true")
@EnableConfigurationProperties(ServiceTokenProperties.class)
public class ServiceTokenConfiguration {
    private static final String SIGNING_KEY_SETTING = "auth.service-token.signing-private-jwk";
    private static final String CALLERS_SETTING = "auth.service-token.callers";

    @Bean
    ServiceTokenSettings serviceTokenSettings(ServiceTokenProperties properties) {
        return new ServiceTokenSettings(properties.issuer(), properties.audience(), properties.lifetime());
    }

    @Bean
    ServiceScopeGrants serviceScopeGrants(ServiceTokenProperties properties) {
        Map<ServiceId, Set<ServiceScope>> grants = new HashMap<>();
        for (Map.Entry<String, ServiceTokenProperties.Caller> callerSetting : properties.callers().entrySet()) {
            ServiceId serviceId = serviceId(callerSetting.getKey());
            Set<ServiceScope> scopes = new HashSet<>();
            for (String code : callerSetting.getValue().scopes()) {
                ServiceScope scope = ServiceScope.fromCode(code).orElseThrow(() -> new IllegalStateException(
                        CALLERS_SETTING + "." + callerSetting.getKey() + ".scopes names an unknown scope"));
                scopes.add(scope);
            }
            grants.put(serviceId, scopes);
        }
        return new ServiceScopeGrants(grants);
    }

    @Bean
    ServiceTokenSigner serviceTokenSigner(ServiceTokenProperties properties) {
        try {
            return new NimbusServiceTokenSigner(signingKey(properties));
        } catch (IllegalArgumentException invalid) {
            throw new IllegalStateException(SIGNING_KEY_SETTING + " is not a private EC P-256 JWK with a kid", invalid);
        }
    }

    @Bean
    IssueServiceTokenUseCase issueServiceTokenUseCase(ServiceScopeGrants serviceScopeGrants,
                                                      ServiceTokenSigner serviceTokenSigner,
                                                      ServiceTokenSettings serviceTokenSettings,
                                                      SecurityAuditStore securityAuditStore,
                                                      Clock clock) {
        return new IssueServiceTokenService(serviceScopeGrants, serviceTokenSigner, UUID::randomUUID, serviceTokenSettings,
                securityAuditStore, clock);
    }

    /** What the JWKS route publishes: the public half of the signing key. */
    @Bean
    ServiceTokenPublicKeys serviceTokenPublicKeys(ServiceTokenProperties properties) {
        return ServiceTokenPublicKeys.of(List.of(signingKey(properties)));
    }

    /** Each calling service's key is pinned; its key ID must be in the JWK because the assertion header has to name it. */
    @Bean
    ServiceClientAssertionVerifier serviceClientAssertionVerifier(ServiceTokenProperties properties, Clock clock) {
        Map<ServiceId, ECKey> clientKeys = new HashMap<>();
        for (Map.Entry<String, ServiceTokenProperties.Caller> callerSetting : properties.callers().entrySet()) {
            String setting = CALLERS_SETTING + "." + callerSetting.getKey() + ".public-jwk";
            ECKey clientKey = publicKey(setting, callerSetting.getValue().publicJwk());
            if (clientKey.getKeyID() == null) {
                throw new IllegalStateException(setting + " has no kid");
            }
            clientKeys.put(serviceId(callerSetting.getKey()), clientKey);
        }
        return new ServiceClientAssertionVerifier(clientKeys, clock);
    }

    /** Used client assertion IDs get their own replay store, told apart from the BFF's by its key factory. */
    @Bean
    ServiceClientAssertionFilter serviceClientAssertionFilter(ServiceClientAssertionVerifier serviceClientAssertionVerifier,
                                                              StringRedisTemplate stringRedisTemplate,
                                                              Clock clock,
                                                              ErrorMessages errorMessages,
                                                              LocaleResolver localeResolver) {
        ValkeyAssertionReplayStore replayStore = new ValkeyAssertionReplayStore(
                stringRedisTemplate, new ServiceClientAssertionKeys(), clock);
        AssertionReplayGuard assertionReplayGuard = replayStore::firstUse;
        return new ServiceClientAssertionFilter(serviceClientAssertionVerifier, assertionReplayGuard, errorMessages, localeResolver);
    }

    @Bean
    ServiceTokenRestMapper serviceTokenRestMapper(ErrorMessages errorMessages) {
        return new ServiceTokenRestMapper(errorMessages);
    }

    private static ServiceId serviceId(String configuredId) {
        try {
            return new ServiceId(configuredId);
        } catch (IllegalArgumentException invalid) {
            throw new IllegalStateException(CALLERS_SETTING + "." + configuredId + " is not a service ID (3-64 of [a-z0-9-])");
        }
    }

    private static ECKey signingKey(ServiceTokenProperties properties) {
        ECKey signingKey;
        try {
            signingKey = ECKey.parse(properties.signingPrivateJwk());
        } catch (ParseException | IllegalArgumentException | ClassCastException invalid) {
            throw new IllegalStateException(SIGNING_KEY_SETTING + " is not a private EC P-256 JWK with a kid");
        }
        if (!signingKey.isPrivate() || !Curve.P_256.equals(signingKey.getCurve()) || signingKey.getKeyID() == null) {
            throw new IllegalStateException(SIGNING_KEY_SETTING + " is not a private EC P-256 JWK with a kid");
        }
        return signingKey;
    }

    private static ECKey publicKey(String setting, String publicJwk) {
        ECKey publicKey;
        try {
            publicKey = ECKey.parse(publicJwk);
        } catch (ParseException | IllegalArgumentException | ClassCastException invalid) {
            throw new IllegalStateException(setting + " is not a public EC P-256 JWK");
        }
        if (publicKey.isPrivate() || !Curve.P_256.equals(publicKey.getCurve())) {
            throw new IllegalStateException(setting + " is not a public EC P-256 JWK");
        }
        return publicKey;
    }
}
