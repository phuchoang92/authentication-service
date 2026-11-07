package com.vpbank.dcp.auth.application.service;

import com.vpbank.dcp.auth.application.port.out.model.CacheTransaction;
import com.vpbank.dcp.auth.application.port.out.model.MfaCheckRequest;
import com.vpbank.dcp.auth.application.port.out.model.MfaTransactionRequest;
import com.vpbank.dcp.auth.domain.enums.EnrollmentPurpose;
import com.vpbank.dcp.auth.domain.enums.MfaFactor;
import com.vpbank.dcp.auth.domain.model.EnrollmentTransaction;
import java.util.List;

/**
 * The two MFA requests of the primary enrollment's FACE check (DD 20 §4): verify creates the check, confirm reads
 * its outcome. Both must name the same purpose, factors and context digest, so they are built here only.
 */
final class FaceCheckRequests {
    /** The primary enrollment asks the customer for FACE alone. */
    private static final List<MfaFactor> FACE_ONLY = List.of(MfaFactor.FACE);
    private static final EnrollmentPurpose PRIMARY_ENROLLMENT = EnrollmentPurpose.TRUST_DEVICE;

    private FaceCheckRequests() {
    }

    /** The FACE transaction lives no longer than the enrollment and is bound to its context digest. */
    static MfaTransactionRequest create(CacheTransaction<EnrollmentTransaction> transaction) {
        EnrollmentTransaction enrollment = transaction.payload();
        return MfaTransactionRequest.builder()
                .customerId(enrollment.customerId())
                .channel(enrollment.channel())
                .authOperationId(enrollment.id())
                .purpose(PRIMARY_ENROLLMENT)
                .factors(FACE_ONLY)
                .notAfter(transaction.expiresAt())
                .contextDigest(EnrollmentDigests.contextDigest(enrollment))
                .build();
    }

    /** Reads the FACE transaction verify created, for the same enrollment and context. */
    static MfaCheckRequest check(EnrollmentTransaction enrollment) {
        return MfaCheckRequest.builder()
                .mfaTransactionId(enrollment.mfaTransactionId())
                .customerId(enrollment.customerId())
                .authOperationId(enrollment.id())
                .purpose(PRIMARY_ENROLLMENT)
                .factors(FACE_ONLY)
                .contextDigest(EnrollmentDigests.contextDigest(enrollment))
                .build();
    }
}
