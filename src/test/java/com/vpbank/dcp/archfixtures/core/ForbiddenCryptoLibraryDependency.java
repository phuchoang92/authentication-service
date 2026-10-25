package com.vpbank.dcp.archfixtures.core;

import com.vpbank.dcp.hpke.XWingHpke;

/** Negative fixture: core must reach X-Wing only through a port, never the library itself. */
public class ForbiddenCryptoLibraryDependency {
    private XWingHpke hpke;
}
