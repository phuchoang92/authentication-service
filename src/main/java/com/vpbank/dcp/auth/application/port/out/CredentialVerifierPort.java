package com.vpbank.dcp.auth.application.port.out;

import com.vpbank.dcp.auth.domain.model.Password;
import com.vpbank.dcp.auth.domain.model.UserName;

/**
 * The identity provider's password check (Keycloak Direct Grant). Throws
 * {@link PartnerUnavailableException} when it cannot answer; a definite "no" is a result.
 */
public interface CredentialVerifierPort {
    VerificationResult verify(UserName userName, Password password);

    sealed interface VerificationResult {
        /** The provider accepted the password and identified the user as issuer + subject. */
        record Verified(String identityIssuer, String identitySubject) implements VerificationResult { }

        record Rejected() implements VerificationResult { }
    }
}
