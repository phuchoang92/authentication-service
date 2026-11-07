package com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.common;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Function;
import lombok.NonNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.SmartLifecycle;

/**
 * A bounded in-memory queue with one background thread that hands items to a {@link BatchWriter} in
 * batches. {@link #offer} never blocks and never throws, so a request path can leave an item here and
 * move on. Any append-only, best-effort table can sit behind it; the first is the security audit.
 *
 * <p>Best-effort by design: a full queue drops the new item, a batch the writer rejects is dropped after
 * a short back-off, and what is still queued when the JVM dies is gone. Drops are counted and logged with
 * the item's label only (never its content). On a clean shutdown the thread is stopped and what remains is
 * written once from the stopping thread.
 */
public final class QueuedBatchWriter<E> implements SmartLifecycle {
    private static final Logger log = LoggerFactory.getLogger(QueuedBatchWriter.class);
    /** Warn on the first drop, then about once per this many, so an outage does not flood the log. */
    private static final int DROP_LOG_EVERY = 1_000;
    /** Pause after a rejected batch, so a store that is down is not hammered with the next one. */
    private static final Duration FAILURE_BACKOFF = Duration.ofMillis(500);

    private final String threadName;
    private final BatchWriter<E> writer;
    private final Function<E, String> labelOf;
    private final BlockingQueue<E> queue;
    private final int batchSize;
    private final Duration shutdownDrain;
    private final AtomicLong droppedCount = new AtomicLong();
    private volatile Thread writerThread;

    /**
     * @param threadName   name of the writer thread, so a thread dump says what it is for
     * @param writer       takes one batch at a time, on the writer thread
     * @param labelOf      a short, non-sensitive label of an item (e.g. its event type) for the drop log
     * @param queueCapacity items held before new ones are dropped
     * @param batchSize    the most items one {@link BatchWriter#write} call carries
     * @param shutdownDrain how long {@link #stop} waits for the thread before writing the rest itself
     */
    public QueuedBatchWriter(@NonNull String threadName,
                             @NonNull BatchWriter<E> writer,
                             @NonNull Function<E, String> labelOf,
                             int queueCapacity,
                             int batchSize,
                             @NonNull Duration shutdownDrain) {
        this.threadName = threadName;
        this.writer = writer;
        this.labelOf = labelOf;
        this.queue = new ArrayBlockingQueue<>(queueCapacity);
        this.batchSize = batchSize;
        this.shutdownDrain = shutdownDrain;
    }

    /** Never blocks, never throws: a full queue costs this one item, not the caller's request. */
    public boolean offer(E item) {
        boolean queued = queue.offer(item);
        if (!queued) {
            countDropped(1, labelOf.apply(item), "queue full");
        }
        return queued;
    }

    /** Items that never reached the store since start; a metric once the project has one. */
    public long droppedCount() {
        return droppedCount.get();
    }

    // --- the writer thread -------------------------------------------------------------------

    @Override
    public void start() {
        writerThread = Thread.ofVirtual().name(threadName).start(this::writeUntilInterrupted);
    }

    /** Stops the thread, waits up to {@code shutdownDrain} for it, then writes what is still queued. */
    @Override
    public void stop() {
        Thread thread = writerThread;
        if (thread != null) {
            thread.interrupt();
            try {
                thread.join(shutdownDrain.toMillis());
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
            }
            writerThread = null;
        }
        writeRemaining();
    }

    @Override
    public boolean isRunning() {
        return writerThread != null;
    }

    private void writeUntilInterrupted() {
        List<E> batch = new ArrayList<>(batchSize);
        while (!Thread.currentThread().isInterrupted()) {
            try {
                batch.add(queue.take());
                queue.drainTo(batch, batchSize - 1);
                writeOrDrop(batch);
            } catch (InterruptedException stopRequested) {
                Thread.currentThread().interrupt();
            } finally {
                batch.clear();
            }
        }
    }

    /** A rejected batch is dropped and the thread lives on: a store outage or a writer bug never ends the audit. */
    private void writeOrDrop(List<E> batch) throws InterruptedException {
        try {
            writer.write(batch);
        } catch (RuntimeException failure) {
            countDropped(batch.size(), labelOf.apply(batch.getFirst()), causeName(failure));
            Thread.sleep(FAILURE_BACKOFF);
        }
    }

    private void writeRemaining() {
        List<E> remaining = new ArrayList<>();
        queue.drainTo(remaining);
        for (int from = 0; from < remaining.size(); from += batchSize) {
            List<E> batch = remaining.subList(from, Math.min(from + batchSize, remaining.size()));
            try {
                writer.write(batch);
            } catch (RuntimeException failure) {
                countDropped(remaining.size() - from, labelOf.apply(batch.getFirst()), causeName(failure));
                return;
            }
        }
    }

    private void countDropped(int count, String label, String why) {
        long total = droppedCount.addAndGet(count);
        boolean firstDrop = total == count;
        boolean passedALogMark = total / DROP_LOG_EVERY > (total - count) / DROP_LOG_EVERY;
        if (firstDrop || passedALogMark) {
            log.warn("{} dropped {} item(s) labelled {} ({}); {} dropped since start", threadName, count, label, why, total);
        }
    }

    private static String causeName(RuntimeException failure) {
        Throwable cause = failure.getCause();
        return cause == null ? failure.getClass().getSimpleName() : cause.getClass().getSimpleName();
    }
}
