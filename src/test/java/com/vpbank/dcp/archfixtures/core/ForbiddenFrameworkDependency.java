package com.vpbank.dcp.archfixtures.core;

import org.springframework.context.ApplicationContext;

/** Negative fixture; never imported into the production application. */
public final class ForbiddenFrameworkDependency {

    private ApplicationContext forbidden;
}
