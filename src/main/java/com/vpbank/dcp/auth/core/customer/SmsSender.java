package com.vpbank.dcp.auth.core.customer;

import java.util.UUID;

/** The Notification service. Throws {@link PartnerUnavailableException} when it cannot answer. */
public interface SmsSender {

    /**
     * True only when Notification accepted responsibility for sending. {@code messageId} is the
     * registration request id, so Notification can drop a duplicate.
     */
    boolean sendInitialPassword(UUID messageId, String customerId, String phone, String userName,
                                String password);
}
