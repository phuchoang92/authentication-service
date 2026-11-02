package com.vpbank.dcp.auth.infrastructure.config;

import com.vpbank.dcp.auth.application.port.out.repository.SecurityAuditStore;
import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.adapter.DisabledSecurityAuditStore;
import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.adapter.QueuedSecurityAuditStore;
import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.adapter.SecurityAuditEventPersistenceAdapter;
import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.repository.SecurityAuditEventJpaRepository;
import java.time.Clock;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * Security activity audit (slice 9). Unlike the other capabilities this one always provides its port,
 * because every login hands its outcome to a {@link SecurityAuditStore}: with {@code auth.audit.enabled}
 * off the store forgets the events; on, a background writer puts them in SECURITY_AUDIT_EVENT.
 */
@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(AuditProperties.class)
public class AuditConfiguration {

    /** Exposed by its concrete type so Spring sees the {@code SmartLifecycle} that starts and stops the writer. */
    @Bean
    @ConditionalOnProperty(prefix = "auth.audit", name = "enabled", havingValue = "true")
    QueuedSecurityAuditStore queuedSecurityAuditStore(AuditProperties properties,
                                                      SecurityAuditEventJpaRepository securityAuditEventJpaRepository,
                                                      PlatformTransactionManager transactionManager,
                                                      Clock clock) {
        SecurityAuditEventPersistenceAdapter writer = new SecurityAuditEventPersistenceAdapter(
                securityAuditEventJpaRepository,
                new TransactionTemplate(transactionManager),
                clock);
        return new QueuedSecurityAuditStore(
                writer,
                properties.queueCapacity(),
                properties.batchSize(),
                properties.shutdownDrain());
    }

    @Bean
    @ConditionalOnProperty(prefix = "auth.audit", name = "enabled", havingValue = "false", matchIfMissing = true)
    SecurityAuditStore disabledSecurityAuditStore() {
        return new DisabledSecurityAuditStore();
    }
}
