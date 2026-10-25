package com.vpbank.dcp.core.password;

/** One Redis atomic gate for DPoP, Kreq JWS and optional Kdev JWS IDs. */
public interface PasswordProofReplay {

    PasswordReplayResult reserve(PasswordReplayAttempt attempt);
}
