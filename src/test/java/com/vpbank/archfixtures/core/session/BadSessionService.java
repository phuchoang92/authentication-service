package com.vpbank.archfixtures.core.session;

import com.vpbank.dcp.core.password.PasswordLoginService;

/** session may import only customer, device and security (ARCHITECTURE.md §4); password must fail. */
public class BadSessionService {
    private PasswordLoginService password;
}
