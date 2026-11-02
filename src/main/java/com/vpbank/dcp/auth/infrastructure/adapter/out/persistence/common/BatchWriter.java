package com.vpbank.dcp.auth.infrastructure.adapter.out.persistence.common;

import com.vpbank.dcp.auth.application.port.out.exception.RepositoryUnavailableException;
import java.util.List;

/**
 * Writes one batch of queued items to a durable store, all or nothing. A {@link RepositoryUnavailableException}
 * means the store did not take the batch; {@link QueuedBatchWriter} then drops it.
 */
@FunctionalInterface
public interface BatchWriter<E> {

    void write(List<E> batch);
}
