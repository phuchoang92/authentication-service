package com.vpbank.dcp.core.port.out.session;

/** Independent security versions confirmed by the authentication source. */
public record SessionSecurityVersions(long customerSecurityVersion,
                                      long credentialSecurityVersion,
                                      long deviceSecurityVersion) {
}
