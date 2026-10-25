package com.vpbank.dcp.infrastructure.adapter.in.web.trusteddevice.dto;

import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

/**
 * A new device presents its X-Wing public key (base64url, 1622 characters); a known device sends
 * none and keeps the stored one.
 */
public record TrustedDeviceInitRequest(@Size(min = 1622, max = 1622) @Pattern(regexp = "[A-Za-z0-9_-]+")
                                       String clientPublicKey) {
}
