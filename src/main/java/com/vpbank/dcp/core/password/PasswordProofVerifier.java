package com.vpbank.dcp.core.password;

import com.vpbank.dcp.core.device.StoredDeviceKey;
/** Cryptographic verification only; replay and owner admission are separate gates. */
public interface PasswordProofVerifier {

    VerifiedPasswordProofs verify(PasswordProofRequest request, StoredDeviceKey deviceKey);
}
