package com.vpbank.dcp.core.port.out.trusteddevice;

import java.util.Objects;

public sealed interface KeyExchangeStart {

    /** {@code exchange} is stored; {@code challengeJwe} is sent to the App. */
    record Started(KeyExchange exchange, String challengeJwe) implements KeyExchangeStart {
        public Started {
            Objects.requireNonNull(exchange, "exchange");
            Objects.requireNonNull(challengeJwe, "challengeJwe");
        }
    }

    /** The presented device key is not a public P-256 key. */
    record InvalidDeviceKey() implements KeyExchangeStart { }
}
