package com.vpbank.dcp.auth.application.port.out.gateway;

import com.vpbank.dcp.auth.domain.model.ServiceTokenClaims;

/**
 * Renders and signs the service token (slice 12): compact JWS, ES256, exactly the claims given, under the
 * service-token signing key. The key and the JOSE library are the adapter's; the application never sees them.
 */
public interface ServiceTokenSigner {
    String sign(ServiceTokenClaims claims);
}
