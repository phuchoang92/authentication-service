package com.vpbank.dcp.core.port.out.replay;

import com.vpbank.dcp.core.domain.security.Digest32;
import java.time.Instant;

/**
 * One use per BFF assertion. Throws {@link ReplayAuthorityUnavailableException} when the marker
 * cannot be recorded; that is never treated as a first use.
 */
public interface AssertionReplay {
    ReplayReservation reserve(Digest32 assertionIdDigest, Instant assertionExpiresAt);
}
