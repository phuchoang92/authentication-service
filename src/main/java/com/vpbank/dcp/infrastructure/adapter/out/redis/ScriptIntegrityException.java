package com.vpbank.dcp.infrastructure.adapter.out.redis;

public final class ScriptIntegrityException extends IllegalStateException {

    public ScriptIntegrityException() {
        super("Authority script integrity check failed");
    }

    public ScriptIntegrityException(Throwable cause) {
        super("Authority script integrity check failed", cause);
    }
}
