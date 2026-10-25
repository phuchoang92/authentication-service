package com.vpbank.dcp.core.password;

/** Makes exactly one password attempt. A timeout is uncertain and must never be retried. */
public interface PasswordVerifier {

    PasswordVerificationOutcome verify(PasswordVerification credential);
}
