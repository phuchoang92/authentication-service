package com.vpbank.dcp.infrastructure.persistence.projection;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

public final class LoginDeviceView {
    private final UUID bindingId;
    private final UUID customerId;
    private final String channel;
    private final String platform;
    private final byte[] deviceIdLookup;
    private final String deviceIdLookupKeyId;
    private final String status;
    private final boolean primary;
    private final Instant expiresAt;
    private final long securityVersion;
    private final byte[] publicKey;
    private final byte[] publicKeyHash;

    public LoginDeviceView(UUID bindingId, UUID customerId, String channel, String platform,
                           byte[] deviceIdLookup, String deviceIdLookupKeyId,
                           String status, boolean primary, Instant expiresAt,
                           long securityVersion, byte[] publicKey, byte[] publicKeyHash) {
        this.bindingId = Objects.requireNonNull(bindingId);
        this.customerId = Objects.requireNonNull(customerId);
        this.channel = Objects.requireNonNull(channel);
        this.platform = Objects.requireNonNull(platform);
        this.deviceIdLookup = deviceIdLookup.clone();
        this.deviceIdLookupKeyId = Objects.requireNonNull(deviceIdLookupKeyId);
        this.status = Objects.requireNonNull(status);
        this.primary = primary;
        this.expiresAt = Objects.requireNonNull(expiresAt);
        this.securityVersion = securityVersion;
        this.publicKey = publicKey.clone();
        this.publicKeyHash = publicKeyHash.clone();
    }

    public UUID bindingId() { return bindingId; }
    public UUID customerId() { return customerId; }
    public String channel() { return channel; }
    public String platform() { return platform; }
    public byte[] deviceIdLookup() { return deviceIdLookup.clone(); }
    public String deviceIdLookupKeyId() { return deviceIdLookupKeyId; }
    public String status() { return status; }
    public boolean primary() { return primary; }
    public Instant expiresAt() { return expiresAt; }
    public long securityVersion() { return securityVersion; }
    public byte[] publicKey() { return publicKey.clone(); }
    public byte[] publicKeyHash() { return publicKeyHash.clone(); }

    @Override
    public String toString() { return "LoginDeviceView[redacted]"; }
}
