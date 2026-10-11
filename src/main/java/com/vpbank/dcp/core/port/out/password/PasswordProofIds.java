package com.vpbank.dcp.core.port.out.password;

import com.vpbank.dcp.core.domain.security.Digest32;
import java.util.Objects;

public record PasswordProofIds(Digest32 dpop, Digest32 requestKey, Digest32 deviceKey) {

    public PasswordProofIds {
        Objects.requireNonNull(dpop, "dpop");
        Objects.requireNonNull(requestKey, "requestKey");
    }
}
