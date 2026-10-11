package com.vpbank.dcp.core.port.out.replay;

/** Reserves one verified DPoP jti across all replicas; uncertainty never permits admission. */
public interface ReplayProtection {

    ReplayReservation reserve(ReplayAttempt attempt);
}
