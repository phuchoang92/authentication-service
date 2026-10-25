package com.vpbank.dcp.auth.application.port.in;

import com.vpbank.dcp.auth.application.result.CaptchaChallenge;

import com.vpbank.dcp.auth.domain.model.UserName;

/**
 * App → Auth (no session): a CAPTCHA for the next login of this user name. Always answers with a
 * challenge, also for an unknown name, so the endpoint cannot probe accounts.
 */
public interface IssueCaptchaUseCase {
    CaptchaChallenge issue(UserName userName);
}
