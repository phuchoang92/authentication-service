package com.vpbank.dcp.core.security;


import java.net.URI;
import java.time.Instant;
import java.util.Objects;

/**
 * Expected server-side DPoP bindings. The exact token is deliberately redacted.
 */
public final class DpopExpectation {

    private final String method;
    private final URI externalUri;
    private final RequestKeyThumbprint requestKey;
    private final String nonce;
    private final String exactToken;
    private final Instant now;

    private DpopExpectation(
            String method,
            URI externalUri,
            RequestKeyThumbprint requestKey,
            String nonce,
            String exactToken,
            Instant now) {
        this.method = Objects.requireNonNull(method, "method");
        this.externalUri = Objects.requireNonNull(externalUri, "externalUri");
        this.requestKey = requestKey;
        this.nonce = nonce;
        this.exactToken = exactToken;
        this.now = Objects.requireNonNull(now, "now");
    }

    public static DpopExpectation forInitial(String method, URI externalUri, Instant now) {
        return new DpopExpectation(method, externalUri, null, null, null, now);
    }

    public static DpopExpectation forAttempt(
            String method, URI externalUri, RequestKeyThumbprint requestKey, String nonce, Instant now) {
        return new DpopExpectation(method, externalUri,
                Objects.requireNonNull(requestKey, "requestKey"),
                Objects.requireNonNull(nonce, "nonce"), null, now);
    }

    public static DpopExpectation forToken(
            String method, URI externalUri, RequestKeyThumbprint requestKey,
            String nonce, String exactToken, Instant now) {
        return new DpopExpectation(method, externalUri,
                Objects.requireNonNull(requestKey, "requestKey"),
                Objects.requireNonNull(nonce, "nonce"),
                Objects.requireNonNull(exactToken, "exactToken"), now);
    }

    public String method() {
        return method;
    }

    public URI externalUri() {
        return externalUri;
    }

    public RequestKeyThumbprint requestKey() {
        return requestKey;
    }

    public String nonce() {
        return nonce;
    }

    public String exactToken() {
        return exactToken;
    }

    public Instant now() {
        return now;
    }

    @Override
    public String toString() {
        return "DpopExpectation[redacted]";
    }
}
