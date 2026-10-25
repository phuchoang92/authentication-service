package com.vpbank.archfixtures.core.device;

import com.vpbank.dcp.core.password.PasswordProofVerifier;

/** device may import only customer and security (ARCHITECTURE.md §4); importing password must fail. */
public class BadDevicePasswordCaller {
    private PasswordProofVerifier proofs;
}
