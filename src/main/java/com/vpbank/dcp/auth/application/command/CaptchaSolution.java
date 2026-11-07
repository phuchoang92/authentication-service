package com.vpbank.dcp.auth.application.command;

import com.vpbank.dcp.auth.domain.model.CaptchaAnswer;
import com.vpbank.dcp.auth.domain.model.CaptchaId;
import lombok.NonNull;

/** The solved CAPTCHA a login carries once the identity has reached the CAPTCHA threshold. */
public record CaptchaSolution(@NonNull CaptchaId captchaId, @NonNull CaptchaAnswer answer) {
}
