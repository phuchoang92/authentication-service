package com.vpbank.dcp.infrastructure.persistence.projection;

public final class LoginDeviceKeyView {
    private final byte[] publicKey;
    private final byte[] thumbprint;

    public LoginDeviceKeyView(byte[] publicKey, byte[] thumbprint) {
        this.publicKey = publicKey.clone();
        this.thumbprint = thumbprint.clone();
    }

    public byte[] publicKey() { return publicKey.clone(); }
    public byte[] thumbprint() { return thumbprint.clone(); }

    @Override
    public String toString() { return "LoginDeviceKeyView[redacted]"; }
}
