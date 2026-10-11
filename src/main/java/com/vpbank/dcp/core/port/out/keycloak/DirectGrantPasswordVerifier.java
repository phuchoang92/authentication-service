package com.vpbank.dcp.core.port.out.keycloak;

/** Makes exactly one password grant attempt. Timeout is uncertain and must not be retried. */
public interface DirectGrantPasswordVerifier {

    PasswordVerificationOutcome verify(PasswordVerification credential);
}
