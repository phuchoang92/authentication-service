package com.vpbank.dcp.auth.infrastructure.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

import com.vpbank.dcp.auth.application.port.out.repository.SecurityAuditStore;
import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.adapter.DisabledSecurityAuditStore;
import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.adapter.QueuedSecurityAuditStore;
import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.repository.SecurityAuditEventJpaRepository;
import java.time.Clock;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.transaction.PlatformTransactionManager;

class AuditConfigurationTest {
    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withUserConfiguration(AuditConfiguration.class)
            .withBean(Clock.class, Clock::systemUTC)
            .withBean(SecurityAuditEventJpaRepository.class, () -> mock(SecurityAuditEventJpaRepository.class))
            .withBean(PlatformTransactionManager.class, () -> mock(PlatformTransactionManager.class));

    @Test
    void offByDefaultTheStoreForgetsEventsAndNoWriterThreadExists() {
        runner.run(context -> {
            assertThat(context).hasNotFailed()
                    .hasSingleBean(SecurityAuditStore.class)
                    .doesNotHaveBean(QueuedSecurityAuditStore.class);
            assertThat(context.getBean(SecurityAuditStore.class)).isInstanceOf(DisabledSecurityAuditStore.class);
            assertThat(Thread.getAllStackTraces().keySet()).extracting(Thread::getName).doesNotContain("security-audit-writer");
        });
    }

    @Test
    void onTheQueuedStoreIsTheOnlyStoreAndItsWriterIsRunning() {
        runner.withPropertyValues("auth.audit.enabled=true").run(context -> {
            assertThat(context).hasNotFailed().hasSingleBean(SecurityAuditStore.class);
            QueuedSecurityAuditStore store = context.getBean(QueuedSecurityAuditStore.class);
            assertThat(store.isRunning()).isTrue();
        });
    }

    @Test
    void aTinyQueueStopsStartupNamingTheSetting() {
        runner.withPropertyValues("auth.audit.enabled=true", "auth.audit.queue-capacity=10").run(context -> {
            assertThat(context).hasFailed();
            assertThat(context.getStartupFailure()).rootCause().hasMessageContaining("queueCapacity");
        });
    }
}
