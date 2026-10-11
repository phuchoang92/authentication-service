package com.vpbank.dcp.infrastructure.adapter.out.redis.codec;

public record SecurityFloor(long customerVersion, long credentialVersion) {

    public SecurityFloor {
        AuthorityNumberCodec.encode(customerVersion);
        AuthorityNumberCodec.encode(credentialVersion);
    }
}
