package com.vpbank.dcp.core.port.out.trusteddevice;

import com.vpbank.dcp.core.domain.device.BindingId;
import java.util.Objects;

public sealed interface TrustActivationResult {

    /** Committed: this binding is trusted and is now the primary one. */
    record Activated(BindingId bindingId) implements TrustActivationResult {
        public Activated {
            Objects.requireNonNull(bindingId, "bindingId");
        }
    }

    /**
     * The customer or device changed since login (status, revocation, a reused key). Nothing was
     * written; the login must start again.
     */
    record Rejected() implements TrustActivationResult { }
}
