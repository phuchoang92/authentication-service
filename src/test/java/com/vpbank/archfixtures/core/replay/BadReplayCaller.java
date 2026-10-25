package com.vpbank.archfixtures.core.replay;

import com.vpbank.dcp.core.session.ExtendSessionService;

/** replay may import only security (ARCHITECTURE.md §4); importing session must fail. */
public class BadReplayCaller {
    private ExtendSessionService sessions;
}
