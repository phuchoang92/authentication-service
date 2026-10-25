package com.vpbank.archfixtures.core.trusteddevice;

import com.vpbank.dcp.core.password.PasswordLoginService;

/** trusteddevice never imports password (ARCHITECTURE.md §4); this must fail. */
public class BadTrustedDevicePasswordCaller {
    private PasswordLoginService passwords;
}
