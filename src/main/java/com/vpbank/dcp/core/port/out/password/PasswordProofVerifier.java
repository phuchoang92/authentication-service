package com.vpbank.dcp.core.port.out.password;

/** Cryptographic verification only; replay and owner admission are separate gates. */
public interface PasswordProofVerifier {

    VerifiedPasswordProofs verify(PasswordProofRequest request, StoredDeviceKey deviceKey);
}
