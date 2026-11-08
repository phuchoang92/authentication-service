package com.vpbank.dcp.auth.infrastructure.adapter.in.rest.constant;

/**
 * The headers a {@code 428 CAPTCHA_REQUIRED} login answer carries (decided 2026-11-08): the challenge rides on
 * the error response, so the app needs no second call. The next login sends the answer in its body.
 */
public final class CaptchaHeaders {
    /** The image to show, PNG as standard base64. */
    public static final String IMAGE = "X-Captcha-Image";
    /** When the challenge stops being accepted, ISO-8601 UTC. */
    public static final String EXPIRES_AT = "X-Captcha-Expires-At";

    private CaptchaHeaders() {
    }
}
