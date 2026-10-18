package com.vpbank.dcp.infrastructure.adapter.out.mfa;

import com.vpbank.dcp.infrastructure.adapter.out.http.ExternalEndpoint;
import com.vpbank.dcp.infrastructure.adapter.out.http.ExternalHttpSettings;
import java.util.Set;

/** The MFA service routes Auth calls (draft doc 20 §5). Any other status fails closed. */
public final class MfaHttpEndpoints {
    static final ExternalEndpoint<MfaCreateResponse, MfaErrorResponse> CREATE =
            ExternalEndpoint.postJson("/internal/v1/transactions", MfaCreateResponse.class,
                    Set.of(200, 201), MfaErrorResponse.class, Set.of(400, 409, 422, 503));
    static final ExternalEndpoint<MfaCheckResponse, MfaErrorResponse> CHECK =
            ExternalEndpoint.postJson("/internal/v1/transactions/{mfaTransactionId}/check",
                    MfaCheckResponse.class, Set.of(200), MfaErrorResponse.class,
                    Set.of(400, 404, 503));

    private MfaHttpEndpoints() {
    }

    public static Set<ExternalHttpSettings.Route> allowedRoutes() {
        return Set.of(CREATE.route(), CHECK.route());
    }
}
