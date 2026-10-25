package com.vpbank.dcp.core.trusteddevice;

import com.vpbank.dcp.core.session.KeyExchange;
import java.util.Objects;

public sealed interface KeyExchangeStart {

    /**
     * {@code exchange} is stored; {@code suite} and {@code protectedChallenge} are sent to the
     * App with the exchange's enrollment ID and server public key.
     */
    record Started(KeyExchange exchange, String suite, String protectedChallenge)
            implements KeyExchangeStart {
        public Started {
            Objects.requireNonNull(exchange, "exchange");
            Objects.requireNonNull(suite, "suite");
            Objects.requireNonNull(protectedChallenge, "protectedChallenge");
        }
    }

    /** The device key is not a usable public key of the supported suite. */
    record InvalidDeviceKey() implements KeyExchangeStart { }
}
