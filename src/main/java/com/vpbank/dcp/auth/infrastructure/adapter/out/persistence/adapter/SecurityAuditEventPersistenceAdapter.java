package com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.adapter;

import com.vpbank.dcp.auth.application.port.out.exception.RepositoryUnavailableException;
import com.vpbank.dcp.auth.application.port.out.model.SecurityAuditEvent;
import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.entity.SecurityAuditEventEntity;
import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.mapper.SecurityAuditPersistenceMapper;
import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.repository.SecurityAuditEventJpaRepository;
import java.time.Clock;
import java.time.Instant;
import java.util.List;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.dao.DataAccessException;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * The synchronous half of the security audit: one batch of events becomes one SQL transaction of
 * inserts into SECURITY_AUDIT_EVENT. It is called from the audit writer's own thread, so the
 * transaction is opened explicitly with a {@link TransactionTemplate} rather than by a proxy
 * annotation that would not see that call.
 */
@RequiredArgsConstructor
public final class SecurityAuditEventPersistenceAdapter {
    @NonNull private final SecurityAuditEventJpaRepository securityAuditEventJpaRepository;
    @NonNull private final TransactionTemplate transactionTemplate;
    @NonNull private final Clock clock;

    /**
     * Inserts the whole batch or nothing. A database failure is reported as
     * {@link RepositoryUnavailableException}; the caller decides what a lost batch means.
     */
    public void writeBatch(List<SecurityAuditEvent> batch) {
        if (batch.isEmpty()) {
            return;
        }
        Instant recordedAt = clock.instant();
        List<SecurityAuditEventEntity> rows = batch.stream()
                .map(event -> SecurityAuditPersistenceMapper.toEntity(event, recordedAt))
                .toList();
        try {
            transactionTemplate.executeWithoutResult(status -> {
                securityAuditEventJpaRepository.saveAll(rows);
                securityAuditEventJpaRepository.flush();
            });
        } catch (DataAccessException failure) {
            throw new RepositoryUnavailableException(failure);
        }
    }
}
