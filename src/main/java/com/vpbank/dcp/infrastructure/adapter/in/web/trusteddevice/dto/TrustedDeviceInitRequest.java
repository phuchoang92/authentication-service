package com.vpbank.dcp.infrastructure.adapter.in.web.trusteddevice.dto;

import com.vpbank.dcp.infrastructure.adapter.in.web.password.dto.P256PublicKeyRequest;
import jakarta.validation.Valid;

/** A new device presents its key; a known device sends none and keeps the stored one. */
public record TrustedDeviceInitRequest(@Valid P256PublicKeyRequest devicePublicJwk) {
}
