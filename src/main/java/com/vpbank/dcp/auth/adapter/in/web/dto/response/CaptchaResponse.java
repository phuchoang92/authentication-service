package com.vpbank.dcp.auth.adapter.in.web.dto.response;

import java.time.Instant;
import java.util.UUID;

/** The challenge: send {@code captchaId} back with the answer; {@code image} is a base64 PNG. */
public record CaptchaResponse(UUID captchaId, String image, Instant expiresAt) { }
