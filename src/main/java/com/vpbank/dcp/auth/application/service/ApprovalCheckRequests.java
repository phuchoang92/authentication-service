package com.vpbank.dcp.auth.application.service;

import com.vpbank.dcp.auth.application.port.out.model.MfaCheckRequest;
import com.vpbank.dcp.auth.application.port.out.model.MfaTransactionRequest;
import com.vpbank.dcp.auth.domain.enums.MfaFactor;
import com.vpbank.dcp.auth.domain.model.DeviceEnrollment;
import java.util.List;

/**
 * The two MFA requests of the primary device's approval (slice 6): approve creates the FACE + OTP check, authorize
 * reads its outcome. Both must name the same purpose, factors and context digest, so they are built here only.
 */
final class ApprovalCheckRequests {
    /** The approving device confirms with FACE and OTP (decision 2026-10-25). */
    private static final List<MfaFactor> FACE_AND_OTP = List.of(MfaFactor.FACE, MfaFactor.OTP);

    private ApprovalCheckRequests() {
    }

    /** The check lives no longer than the request and is bound to its context digest. */
    static MfaTransactionRequest create(DeviceEnrollment request) {
        return MfaTransactionRequest.builder()
                .customerId(request.customerId())
                .channel(request.channel())
                .authOperationId(request.id())
                .purpose(request.purpose())
                .factors(FACE_AND_OTP)
                .notAfter(request.expiresAt())
                .contextDigest(EnrollmentDigests.contextDigest(request))
                .build();
    }

    /** Reads the check approve created, for the same request and context. */
    static MfaCheckRequest check(DeviceEnrollment request) {
        return MfaCheckRequest.builder()
                .mfaTransactionId(request.mfaTransactionId())
                .customerId(request.customerId())
                .authOperationId(request.id())
                .purpose(request.purpose())
                .factors(FACE_AND_OTP)
                .contextDigest(EnrollmentDigests.contextDigest(request))
                .build();
    }
}
