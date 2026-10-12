package com.vpbank.dcp.infrastructure.adapter.out.crypto;

import com.vpbank.dcp.core.domain.security.Digest32;
import java.io.IOException;
import java.util.Objects;
import org.erdtman.jcs.JsonCanonicalizer;

/** RFC 8785 digest of the original typed enrollment command without enrollmentProof. */
public final class JcsCommandDigest {

    private final StrictJoseJson strictJson;
    private final Sha256Digests digests;

    public JcsCommandDigest(StrictJoseJson strictJson, Sha256Digests digests) {
        this.strictJson = Objects.requireNonNull(strictJson, "strictJson");
        this.digests = Objects.requireNonNull(digests, "digests");
    }

    public Digest32 ofCommand(String commandWithoutProof) {
        Objects.requireNonNull(commandWithoutProof, "commandWithoutProof");
        strictJson.checkJson(commandWithoutProof);
        try {
            return digests.sha256(new JsonCanonicalizer(commandWithoutProof).getEncodedUTF8());
        } catch (IOException failure) {
            throw new InvalidCryptographicInputException(failure);
        }
    }
}
