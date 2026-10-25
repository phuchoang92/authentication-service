package com.vpbank.archfixtures.core.customer;

import com.vpbank.dcp.core.password.PasswordLoginService;

/** customer may import only security (ARCHITECTURE.md §4); importing password must fail. */
public class BadCustomerLoginService {
    private PasswordLoginService password;
}
