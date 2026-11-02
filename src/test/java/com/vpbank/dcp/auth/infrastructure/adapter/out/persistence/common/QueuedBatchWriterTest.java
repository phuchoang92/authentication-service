package com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.common;

import static org.assertj.core.api.Assertions.assertThat;

import com.vpbank.dcp.auth.application.port.out.exception.RepositoryUnavailableException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/** The queue and its thread with a lambda as the store: batching, dropping, surviving a failure or a bug, draining on stop. */
class QueuedBatchWriterTest {
    private final List<List<String>> batches = new CopyOnWriteArrayList<>();
    private final List<String> writerThreads = new CopyOnWriteArrayList<>();
    private QueuedBatchWriter<String> queue;

    @AfterEach
    void stopThread() {
        if (queue != null) {
            queue.stop();
        }
    }

    @Test
    void itemsAreWrittenInOneBatchOffTheCallersThread() throws Exception {
        CountDownLatch written = new CountDownLatch(1);
        queue = writer(100, 10, batch -> {
            batches.add(new ArrayList<>(batch));
            writerThreads.add(Thread.currentThread().getName());
            written.countDown();
        });

        assertThat(queue.offer("a")).isTrue();
        assertThat(queue.offer("b")).isTrue();
        assertThat(queue.offer("c")).isTrue();
        queue.start();

        assertThat(written.await(2, TimeUnit.SECONDS)).isTrue();
        assertThat(batches).containsExactly(List.of("a", "b", "c"));
        assertThat(writerThreads).containsExactly("test-writer");
        assertThat(queue.droppedCount()).isZero();
    }

    @Test
    void aFullQueueDropsTheNewItemCountsItAndTheCallerReturnsAtOnce() throws Exception {
        CountDownLatch writerBusy = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        queue = writer(2, 1, batch -> {
            writerBusy.countDown();
            awaitQuietly(release);
        });
        queue.start();

        queue.offer("taken"); // taken by the writer, which now blocks inside write
        assertThat(writerBusy.await(2, TimeUnit.SECONDS)).isTrue();
        assertThat(queue.offer("slot-1")).isTrue();
        assertThat(queue.offer("slot-2")).isTrue();
        long before = System.nanoTime();
        boolean queued = queue.offer("no-room");
        long elapsedMillis = Duration.ofNanos(System.nanoTime() - before).toMillis();

        assertThat(queued).isFalse();
        assertThat(queue.droppedCount()).isEqualTo(1);
        assertThat(elapsedMillis).isLessThan(100);
        release.countDown();
    }

    @Test
    void aRejectedBatchIsDroppedAndTheWriterKeepsGoing() throws Exception {
        AtomicInteger calls = new AtomicInteger();
        CountDownLatch firstBatchRejected = new CountDownLatch(1);
        CountDownLatch secondBatchWritten = new CountDownLatch(1);
        queue = writer(100, 10, batch -> {
            if (calls.incrementAndGet() == 1) {
                firstBatchRejected.countDown();
                throw new RepositoryUnavailableException(new IllegalStateException("database away"));
            }
            batches.add(new ArrayList<>(batch));
            secondBatchWritten.countDown();
        });
        queue.offer("lost-1");
        queue.offer("lost-2");
        queue.start();

        assertThat(firstBatchRejected.await(2, TimeUnit.SECONDS)).isTrue();
        queue.offer("kept"); // arrives during the back-off after the rejected batch

        assertThat(secondBatchWritten.await(3, TimeUnit.SECONDS)).isTrue();
        assertThat(queue.droppedCount()).isEqualTo(2);
        assertThat(batches).containsExactly(List.of("kept"));
    }

    @Test
    void aBugInTheWriterCostsThatBatchNotTheThread() throws Exception {
        AtomicInteger calls = new AtomicInteger();
        CountDownLatch bugHit = new CountDownLatch(1);
        CountDownLatch secondBatchWritten = new CountDownLatch(1);
        queue = writer(100, 10, batch -> {
            if (calls.incrementAndGet() == 1) {
                bugHit.countDown();
                throw new NullPointerException("mapper bug");
            }
            batches.add(new ArrayList<>(batch));
            secondBatchWritten.countDown();
        });
        queue.offer("lost");
        queue.start();

        assertThat(bugHit.await(2, TimeUnit.SECONDS)).isTrue();
        queue.offer("kept");

        assertThat(secondBatchWritten.await(3, TimeUnit.SECONDS)).isTrue();
        assertThat(queue.isRunning()).isTrue();
        assertThat(queue.droppedCount()).isEqualTo(1);
        assertThat(batches).containsExactly(List.of("kept"));
    }

    @Test
    void stopWritesWhatIsStillQueuedInBatchesOfTheConfiguredSize() {
        queue = writer(100, 2, batch -> batches.add(new ArrayList<>(batch)));
        queue.offer("a");
        queue.offer("b");
        queue.offer("c");

        queue.stop();

        assertThat(batches).containsExactly(List.of("a", "b"), List.of("c"));
        assertThat(queue.isRunning()).isFalse();
        queue = null;
    }

    private static QueuedBatchWriter<String> writer(int capacity, int batchSize, BatchWriter<String> store) {
        return new QueuedBatchWriter<>("test-writer", store, item -> "label", capacity, batchSize, Duration.ofSeconds(1));
    }

    private static void awaitQuietly(CountDownLatch latch) {
        try {
            latch.await();
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
        }
    }
}
