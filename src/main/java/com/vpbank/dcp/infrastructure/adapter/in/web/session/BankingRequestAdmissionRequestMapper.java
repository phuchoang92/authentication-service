package com.vpbank.dcp.infrastructure.adapter.in.web.session;

import com.vpbank.dcp.core.port.in.session.BankingRequestAdmissionCommand;
import com.vpbank.dcp.infrastructure.adapter.in.web.ExternalUriPolicy;
import java.net.URI;
import java.util.Objects;

/** BFF cannot choose a different action/audience than the trusted original route. */
public final class BankingRequestAdmissionRequestMapper {
    private final ExternalUriPolicy externalUris;

    public BankingRequestAdmissionRequestMapper(ExternalUriPolicy externalUris) {
        this.externalUris = Objects.requireNonNull(externalUris);
    }

    public BankingRequestAdmissionCommand map(BankingRequestAdmissionRequest request) {
        if (request == null || request.original() == null) {
            throw new InvalidBankingAdmissionRequestException();
        }
        var original = request.original();
        URI expected = externalUris.forPath("/api/v1/accounts");
        if (!"GET".equals(original.method())
                || !expected.toString().equals(original.publicUri())
                || !"ACCOUNT_READ".equals(request.targetAction())
                || !"account-service".equals(request.audience())
                || original.opaqueToken() == null || original.opaqueToken().length() > 80
                || original.dpopProof() == null || original.dpopProof().length() > 8192
                || (original.bodyBase64() != null && !original.bodyBase64().isEmpty())) {
            throw new InvalidBankingAdmissionRequestException();
        }
        return new BankingRequestAdmissionCommand(original.opaqueToken(), original.dpopProof(),
                "GET", expected, request.targetAction(), request.audience());
    }
}
