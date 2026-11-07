package com.vpbank.dcp.auth.application.command;

import com.vpbank.dcp.auth.domain.enums.DevicePlatform;
import com.vpbank.dcp.auth.domain.model.AdmittedSession;
import lombok.NonNull;

/**
 * Slice 6: a new device on a restricted session asks the primary device to approve it. The key and
 * platform may be absent when the installation already has a live row (its stored values are kept).
 */
public record RequestApprovalCommand(@NonNull AdmittedSession admitted,
                                     String devicePublicJwk,
                                     DevicePlatform platform) {
    @Override
    public String toString() {
        return "RequestApprovalCommand[platform=" + platform + ", redacted]";
    }
}
