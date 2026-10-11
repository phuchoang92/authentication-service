package com.vpbank.dcp.infrastructure.adapter.in.web.session;

import com.vpbank.dcp.infrastructure.adapter.in.web.password.ForwardPasswordRequest;

public record ForwardAdmissionRequest(ForwardPasswordRequest.Original original,
                                      String targetAction, String audience) {
    @Override public String toString() { return "ForwardAdmissionRequest[redacted]"; }
}
