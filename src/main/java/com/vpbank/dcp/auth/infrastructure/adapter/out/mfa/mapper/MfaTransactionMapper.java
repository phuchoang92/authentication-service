package com.vpbank.dcp.auth.infrastructure.adapter.out.mfa.mapper;

import com.vpbank.dcp.auth.application.port.out.model.MfaTransactionRequest;
import com.vpbank.dcp.auth.domain.model.EnrollmentId;
import com.vpbank.dcp.auth.infrastructure.adapter.out.mfa.dto.CheckTransactionRequest;
import com.vpbank.dcp.auth.infrastructure.adapter.out.mfa.dto.CreateTransactionRequest;
import java.util.List;

/** Port values → MFA wire bodies. */
public final class MfaTransactionMapper {
    private MfaTransactionMapper() {
    }

    public static CreateTransactionRequest toCreate(MfaTransactionRequest request) {
        return CreateTransactionRequest.builder()
                .purpose(MfaTransactionRequest.PURPOSE)
                .customerNumber(request.customerId().value())
                .channel(request.channel().name())
                .authOperationId(request.authOperationId().value().toString())
                .factors(List.of("FACE"))
                .notAfter(request.notAfter())
                .contextDigest(request.contextDigest())
                .build();
    }

    public static CheckTransactionRequest toCheck(EnrollmentId authOperationId, String contextDigest) {
        return new CheckTransactionRequest(authOperationId.value().toString(), contextDigest);
    }
}
