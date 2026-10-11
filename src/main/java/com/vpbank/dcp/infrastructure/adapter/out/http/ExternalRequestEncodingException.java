package com.vpbank.dcp.infrastructure.adapter.out.http;

/** A local request DTO could not be serialized; this is not a partner outage. */
public final class ExternalRequestEncodingException extends RuntimeException {

    public ExternalRequestEncodingException(Throwable cause) {
        super("External request could not be encoded", cause);
    }
}
