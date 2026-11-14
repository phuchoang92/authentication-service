package com.vpbank.dcp.auth.domain.model;

import com.vpbank.dcp.auth.domain.enums.Channel;
import com.vpbank.dcp.auth.domain.enums.DevicePlatform;
import com.vpbank.dcp.auth.domain.enums.DeviceStatus;
import com.vpbank.dcp.auth.domain.enums.TrustLevel;
import java.time.Instant;

/**
 * Rows and sessions the tests start from; rows get a fresh random ID. A trusted row is built as the store would
 * hold it, so a test may give it no key, like a row trusted before slice 13; production only creates rows through
 * the factories.
 */
public final class DomainFixtures {
    private DomainFixtures() {
    }

    /** An ACTIVE, TRUSTED row of the installation, trusted (and last logged in) at {@code trustedAt}. */
    public static TrustedDevice trustedDevice(DeviceInstallation installation, DevicePlatform platform,
                                              String publicKey, Instant trustedAt) {
        return TrustedDevice.builder()
                .id(TrustedDeviceId.random())
                .customerId(installation.customerId())
                .channel(installation.channel())
                .deviceId(installation.deviceId())
                .platform(platform)
                .status(DeviceStatus.ACTIVE)
                .trustLevel(TrustLevel.TRUSTED)
                .trustedAt(trustedAt)
                .expiresAt(trustedAt.plus(DevicePolicy.standard().trustDuration()))
                .lastLoginAt(trustedAt)
                .publicKey(publicKey)
                .version(0)
                .build();
    }

    /** A row about to be created for the installation with this key. */
    public static NewDevice newDevice(DeviceInstallation installation, DevicePlatform platform, String publicJwk,
                                      Instant createdAt) {
        return NewDevice.builder()
                .id(TrustedDeviceId.random())
                .installation(installation)
                .key(new DeviceKey(publicJwk, platform))
                .createdAt(createdAt)
                .build();
    }

    /** A MOBILE session about to start; {@code deviceId} may be null like a session whose app sent none. */
    public static NewSession mobileSession(SessionId id, CustomerId customerId, DeviceId deviceId, Instant startedAt) {
        return NewSession.builder()
                .id(id)
                .customerId(customerId)
                .channel(Channel.MOBILE)
                .deviceId(deviceId)
                .startedAt(startedAt)
                .build();
    }

    /** The installation's approval request for the target row, open until {@code expiresAt}. */
    public static DeviceEnrollment approvalRequest(DeviceInstallation requester, TrustedDeviceId targetDeviceId,
                                                   Instant expiresAt) {
        ApprovalRequestStart start = ApprovalRequestStart.builder()
                .enrollmentId(EnrollmentId.random())
                .requester(requester)
                .candidateKey(new DeviceKey("{candidate-key}", DevicePlatform.IOS))
                .targetDeviceId(targetDeviceId)
                .expiresAt(expiresAt)
                .build();
        return DeviceEnrollment.requestApproval(start);
    }
}
