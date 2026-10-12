package com.vpbank.dcp.infrastructure.adapter.in.web.session;

import com.vpbank.dcp.infrastructure.adapter.in.web.ForwardedPublicRequest;

public record BankingRequestAdmissionRequest(ForwardedPublicRequest original,
                                             String targetAction, String audience) {
    @Override public String toString() { return "BankingRequestAdmissionRequest[redacted]"; }
}
