package com.vpbank.dcp.core.password;

import com.vpbank.dcp.core.security.Digest32;
import java.util.Objects;

public record PasswordProofIds(Digest32 dpop, Digest32 requestKey, Digest32 deviceKey) {

    public PasswordProofIds {
        Objects.requireNonNull(dpop, "dpop");
        Objects.requireNonNull(requestKey, "requestKey");
    }
}
