package com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.adapter;

import com.vpbank.dcp.auth.application.port.out.model.SecurityAuditEvent;
import com.vpbank.dcp.auth.application.port.out.repository.SecurityAuditStore;
import com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.common.QueuedBatchWriter;
import org.springframework.context.SmartLifecycle;

import java.time.Duration;

/**
 * The asynchronous half of the security audit: a {@link QueuedBatchWriter} in front of
 * {@link SecurityAuditEventPersistenceAdapter#writeBatch}. {@link #record} leaves the event on the queue
 * and returns; the writer thread {@code security-audit-writer} inserts it later, in batches. Nothing here can
 * slow down or fail a login; under overload events are dropped and counted (see the queue's contract).
 */
public final class QueuedSecurityAuditStore implements SecurityAuditStore, SmartLifecycle {
    private final QueuedBatchWriter<SecurityAuditEvent> queue;

    public QueuedSecurityAuditStore(SecurityAuditEventPersistenceAdapter writer,
                                    int queueCapacity,
                                    int batchSize,
                                    Duration shutdownDrain) {
        this.queue = new QueuedBatchWriter<>(
                "security-audit-writer",
                writer::writeBatch,
                event -> event.eventType().name(),
                queueCapacity,
                batchSize,
                shutdownDrain);
    }

    @Override
    public void record(SecurityAuditEvent event) {
        queue.offer(event);
    }

    /**
     * Events that never reached SECURITY_AUDIT_EVENT since start.
     */
    public long droppedCount() {
        return queue.droppedCount();
    }

    @Override
    public void start() {
        queue.start();
    }

    @Override
    public void stop() {
        queue.stop();
    }

    @Override
    public boolean isRunning() {
        return queue.isRunning();
    }
}
