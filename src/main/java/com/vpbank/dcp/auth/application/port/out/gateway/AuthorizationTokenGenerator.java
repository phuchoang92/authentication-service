package com.vpbank.dcp.auth.application.port.out.gateway;

/** The one-time QR authorization token of slice 6: 32 random bytes as unpadded base64url. Never stored in clear. */
public interface AuthorizationTokenGenerator {
    String next();
}
