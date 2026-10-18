package com.vpbank.dcp.infrastructure.adapter.out.crypto;

import com.vpbank.dcp.core.domain.security.LookupKeyVersion;
import com.vpbank.dcp.core.port.out.pending.InvalidPendingTokenException;
import com.vpbank.dcp.core.port.out.pending.PendingTokenLookup;
import com.vpbank.dcp.core.port.out.session.SessionTokenLookup;
import java.util.Objects;

public final class HmacPendingTokenLookup implements PendingTokenLookup {
    private final TokenLookupHasher hasher;
    private final LookupKeyVersion version;

    public HmacPendingTokenLookup(TokenLookupHasher hasher, LookupKeyVersion version) {
        this.hasher = Objects.requireNonNull(hasher);
        this.version = Objects.requireNonNull(version);
    }

    @Override
    public SessionTokenLookup forExactToken(String exactToken) {
        try {
            return new SessionTokenLookup(version, hasher.digest(exactToken));
        } catch (InvalidCryptographicInputException failure) {
            throw new InvalidPendingTokenException();
        }
    }
}
