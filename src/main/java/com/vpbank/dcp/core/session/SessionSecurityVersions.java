package com.vpbank.dcp.core.session;

/** Independent security versions confirmed by the authentication source. */
public record SessionSecurityVersions(long customerSecurityVersion,
                                      long credentialSecurityVersion,
                                      long deviceSecurityVersion) {
}
