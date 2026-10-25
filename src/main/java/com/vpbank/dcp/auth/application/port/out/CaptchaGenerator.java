package com.vpbank.dcp.auth.application.port.out;

import com.vpbank.dcp.auth.domain.model.CaptchaAnswer;

/** Draws a challenge. Randomness and image rendering are boundaries, so this is a port. */
public interface CaptchaGenerator {
    GeneratedCaptcha next();

    /** The answer and the image that shows it. */
    record GeneratedCaptcha(CaptchaAnswer answer, byte[] imagePng) {
        @Override
        public String toString() {
            return "GeneratedCaptcha[redacted]";
        }
    }
}
