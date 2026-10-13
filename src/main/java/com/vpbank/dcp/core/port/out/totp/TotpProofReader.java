package com.vpbank.dcp.core.port.out.totp;

import com.vpbank.dcp.core.domain.totp.TotpCode;
import java.time.Instant;

/** Decrypts a proof bound to the Auth-owned challenge and admitted request key. */
public interface TotpProofReader {
    TotpCode read(String compactJwe, String challengeId, String requestKeyThumbprint, Instant now);
}
