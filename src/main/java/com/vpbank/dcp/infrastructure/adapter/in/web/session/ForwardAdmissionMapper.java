package com.vpbank.dcp.infrastructure.adapter.in.web.session;

import com.vpbank.dcp.core.application.session.BankingAdmissionCommand;
import com.vpbank.dcp.infrastructure.adapter.in.web.ExternalUriPolicy;
import java.net.URI;
import java.util.Objects;

/** BFF cannot choose a different action/audience than the trusted original route. */
public final class ForwardAdmissionMapper {
    private final ExternalUriPolicy externalUris;

    public ForwardAdmissionMapper(ExternalUriPolicy externalUris) {
        this.externalUris = Objects.requireNonNull(externalUris);
    }

    public BankingAdmissionCommand map(ForwardAdmissionRequest request) {
        if (request == null || request.original() == null) {
            throw new InvalidForwardAdmissionException();
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
            throw new InvalidForwardAdmissionException();
        }
        return new BankingAdmissionCommand(original.opaqueToken(), original.dpopProof(),
                "GET", expected, request.targetAction(), request.audience());
    }
}
