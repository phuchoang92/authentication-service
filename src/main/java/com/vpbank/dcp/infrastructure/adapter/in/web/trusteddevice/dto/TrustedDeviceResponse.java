package com.vpbank.dcp.infrastructure.adapter.in.web.trusteddevice.dto;

/** Bodies of the init and verify steps. */
public sealed interface TrustedDeviceResponse
        permits TrustedDeviceInitResponse, TrustedDeviceVerifyResponse, TrustedDeviceErrorResponse {
}
