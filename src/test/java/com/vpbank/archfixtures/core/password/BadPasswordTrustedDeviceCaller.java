package com.vpbank.archfixtures.core.password;

import com.vpbank.dcp.core.trusteddevice.TrustedDeviceService;

/** password never imports trusteddevice (ARCHITECTURE.md §4); this must fail. */
public class BadPasswordTrustedDeviceCaller {
    private TrustedDeviceService trustedDevices;
}
