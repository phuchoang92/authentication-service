package com.vpbank.dcp.auth.application.service;

import com.vpbank.dcp.auth.application.port.out.model.TransactionKind;
import com.vpbank.dcp.auth.domain.model.AdmittedSession;
import com.vpbank.dcp.auth.domain.model.EnrollmentTransaction;

/**
 * How the primary enrollment uses the cache transaction store (slice 11): one kind, and one transaction per
 * device, addressed by the admitted session's channel, customer and device.
 */
final class EnrollmentTransactions {
    static final TransactionKind<EnrollmentTransaction> KIND =
            new TransactionKind<>("enrollment", EnrollmentTransaction.class);

    private EnrollmentTransactions() {
    }

    /**
     * The device's transaction address: a device enrolls once at a time, from whichever login started it.
     */
    static String idOf(AdmittedSession caller) {
        return caller.channel().name() + ":" + caller.customerId().value() + ":" + caller.deviceId().value();
    }
}
