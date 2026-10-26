package com.vpbank.dcp.auth.infrastructure.adapter.out.mfa.mapper;

import com.vpbank.dcp.auth.application.port.out.model.MfaCheckRequest;
import com.vpbank.dcp.auth.application.port.out.model.MfaTransactionRequest;
import com.vpbank.dcp.auth.domain.enums.MfaFactor;
import com.vpbank.dcp.auth.domain.model.EnrollmentId;
import com.vpbank.dcp.auth.infrastructure.adapter.out.mfa.dto.CheckTransactionRequest;
import com.vpbank.dcp.auth.infrastructure.adapter.out.mfa.dto.CreateTransactionRequest;
import java.util.ArrayList;
import java.util.List;

/** Port values → MFA wire bodies. */
public final class MfaTransactionMapper {
    private MfaTransactionMapper() {
    }

    public static CreateTransactionRequest toCreate(MfaTransactionRequest request) {
        return CreateTransactionRequest.builder()
                .purpose(request.purpose().name())
                .customerNumber(request.customerId().value())
                .channel(request.channel().name())
                .authOperationId(request.authOperationId().value().toString())
                .factors(factorNames(request.factors()))
                .notAfter(request.notAfter())
                .contextDigest(request.contextDigest())
                .build();
    }

    public static CheckTransactionRequest toCheck(MfaCheckRequest request) {
        return new CheckTransactionRequest(request.authOperationId().value().toString(), request.contextDigest());
    }

    private static List<String> factorNames(List<MfaFactor> factors) {
        List<String> names = new ArrayList<>();
        for (MfaFactor factor : factors) {
            names.add(factor.name());
        }
        return names;
    }
}
