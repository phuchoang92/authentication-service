package com.vpbank.dcp.auth.application.port.out.gateway;

import com.vpbank.dcp.auth.application.port.out.model.ServerKeyPair;

/** A fresh P-256 pair (Ksrv) per trust transaction (DD 20 §4); randomness is a boundary. */
public interface ServerKeyPairGenerator {
    ServerKeyPair next();
}
