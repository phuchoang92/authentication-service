package com.vpbank.dcp.auth.infrastructure.adapter.in.rest.constant;

/**
 * The headers a login carries besides its JSON body (App contract §2): the channel, the installation and,
 * for a trusted device, the proof that it still holds its key (slice 13).
 */
public final class DeviceHeaders {
    public static final String CHANNEL = "X-Channel";
    public static final String DEVICE_ID = "X-Device-Id";
    public static final String DEVICE_OS = "X-Device-OS";
    /** {@code <issuedAt epoch seconds>.<nonce>.<signature>}, the last two base64url without padding. */
    public static final String DEVICE_PROOF = "X-Device-Proof";

    private DeviceHeaders() {
    }
}
