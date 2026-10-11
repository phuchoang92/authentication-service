package com.vpbank.dcp.infrastructure.adapter.out.redis;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Objects;
import org.springframework.core.io.ClassPathResource;
import org.springframework.data.redis.core.script.DefaultRedisScript;

/** Loads a reviewed Lua script only when its source bytes match the pinned checksum. */
public final class VerifiedAuthorityScript {

    private VerifiedAuthorityScript() {
    }

    public static DefaultRedisScript<String> load(String resourcePath, String expectedSha256) {
        Objects.requireNonNull(resourcePath, "resourcePath");
        Objects.requireNonNull(expectedSha256, "expectedSha256");
        try {
            ClassPathResource resource = new ClassPathResource(resourcePath);
            byte[] source = resource.getInputStream().readAllBytes();
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            String actual = HexFormat.of().formatHex(sha256.digest(source));
            if (!actual.equals(expectedSha256)) {
                throw new ScriptIntegrityException();
            }
            DefaultRedisScript<String> script = new DefaultRedisScript<>();
            script.setScriptText(new String(source, StandardCharsets.UTF_8));
            script.setResultType(String.class);
            return script;
        } catch (IOException | NoSuchAlgorithmException failure) {
            throw new ScriptIntegrityException(failure);
        }
    }
}
