package com.vpbank.dcp.core.application.password;

/** App signatures verified and replay markers reserved, or the login ends here. */
public sealed interface PasswordProofAdmissionResult {

    record Admitted(AdmittedProof proof) implements PasswordProofAdmissionResult { }

    record Denied(LoginDenial why) implements PasswordProofAdmissionResult { }
}
