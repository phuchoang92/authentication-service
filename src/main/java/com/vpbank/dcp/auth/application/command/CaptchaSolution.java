package com.vpbank.dcp.auth.application.command;

import com.vpbank.dcp.auth.domain.model.CaptchaAnswer;
import com.vpbank.dcp.auth.domain.model.CaptchaId;
import java.util.Objects;

/** The solved CAPTCHA a login carries once the identity has reached the CAPTCHA threshold. */
public record CaptchaSolution(CaptchaId captchaId, CaptchaAnswer answer) {
    public CaptchaSolution {
        Objects.requireNonNull(captchaId, "captchaId");
        Objects.requireNonNull(answer, "answer");
    }
}
