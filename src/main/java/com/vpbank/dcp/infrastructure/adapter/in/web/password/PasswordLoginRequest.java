package com.vpbank.dcp.infrastructure.adapter.in.web.password;

import com.vpbank.dcp.infrastructure.adapter.in.web.ForwardedPublicRequest;

/** BFF forwards the original bytes once, without a second password copy. */
public record PasswordLoginRequest(ForwardedPublicRequest original) {
    @Override public String toString() { return "PasswordLoginRequest[redacted]"; }
}
