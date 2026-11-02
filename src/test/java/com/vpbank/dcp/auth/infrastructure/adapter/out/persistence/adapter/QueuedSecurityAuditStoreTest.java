package com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.adapter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;

import com.vpbank.dcp.auth.application.port.out.model.SecurityAuditEvent;
import com.vpbank.dcp.auth.domain.enums.Channel;
import com.vpbank.dcp.auth.domain.enums.SecurityEventReason;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;

/** The store is the queue in front of the SQL writer; the queue's own behaviour is proven in QueuedBatchWriterTest. */
class QueuedSecurityAuditStoreTest {
    private final SecurityAuditEventPersistenceAdapter writer = mock(SecurityAuditEventPersistenceAdapter.class);
    private final List<List<SecurityAuditEvent>> batches = new CopyOnWriteArrayList<>();

    @Test
    void aRecordedEventReachesTheSqlWriterFromTheAuditThreadAndNothingIsDropped() throws Exception {
        CountDownLatch written = new CountDownLatch(1);
        List<String> threads = new CopyOnWriteArrayList<>();
        doAnswer(call -> {
            batches.add(new ArrayList<>(call.getArgument(0)));
            threads.add(Thread.currentThread().getName());
            written.countDown();
            return null;
        }).when(writer).writeBatch(anyList());
        QueuedSecurityAuditStore store = new QueuedSecurityAuditStore(writer, 100, 10, Duration.ofSeconds(1));
        store.start();
        try {
            SecurityAuditEvent event = event();
            store.record(event);

            assertThat(written.await(2, TimeUnit.SECONDS)).isTrue();
            assertThat(batches).containsExactly(List.of(event));
            assertThat(threads).containsExactly("security-audit-writer");
            assertThat(store.droppedCount()).isZero();
        } finally {
            store.stop();
        }
    }

    @Test
    void beforeTheThreadRunsAFullQueueDropsAndCountsAndStopWritesTheRest() {
        doAnswer(call -> {
            batches.add(new ArrayList<>(call.getArgument(0)));
            return null;
        }).when(writer).writeBatch(anyList());
        QueuedSecurityAuditStore store = new QueuedSecurityAuditStore(writer, 1, 10, Duration.ofSeconds(1));

        store.record(event());
        store.record(event()); // no slot: dropped
        store.stop();

        assertThat(store.droppedCount()).isEqualTo(1);
        assertThat(batches).hasSize(1);
        assertThat(batches.getFirst()).hasSize(1);
    }

    private static SecurityAuditEvent event() {
        return SecurityAuditEvent.builder()
                .reason(SecurityEventReason.UNKNOWN_USER)
                .channel(Channel.WEB)
                .occurredAt(Instant.parse("2026-10-31T09:00:00Z"))
                .build();
    }
}
