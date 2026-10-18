package com.vpbank.dcp.infrastructure.adapter.out.crypto;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.crypto.factories.DefaultJWSVerifierFactory;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.vpbank.dcp.core.domain.security.Digest32;
import com.vpbank.dcp.core.port.out.security.VerifiedDpopProof;
import com.vpbank.dcp.core.port.out.password.PasswordOperationContext;
import com.vpbank.dcp.core.port.out.password.InvalidPasswordProofException;
import com.vpbank.dcp.core.port.out.password.PasswordProofIds;
import com.vpbank.dcp.core.port.out.password.PasswordProofRequest;
import com.vpbank.dcp.core.port.out.password.PasswordProofVerifier;
import com.vpbank.dcp.core.port.out.password.StoredDeviceKey;
import com.vpbank.dcp.core.port.out.password.VerifiedPasswordProofs;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.interfaces.ECPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.text.ParseException;
import java.time.Instant;
import java.util.Base64;
import java.util.Objects;
import java.util.Set;

/** Verifies one-shot Kreq/Kdev proofs without interpreting password or customer status. */
public final class JosePasswordProofVerifier implements PasswordProofVerifier {

    private static final Set<String> KEY_CLAIMS = Set.of("v", "purpose", "operationId",
            "appId", "platform", "installationHash", "username", "deviceBindingId",
            "requestKeyJkt", "responseKeyJkt", "iat", "exp", "jti");
    private static final Set<String> DEVICE_CLAIMS = Set.of("v", "purpose", "operationId",
            "appId", "platform", "installationHash", "username", "deviceBindingId",
            "requestKeyJkt", "responseKeyJkt", "deviceKeyJkt", "iat", "exp", "jti");
    private static final Set<String> JWS_HEADERS = Set.of("alg", "kid", "typ");
    private static final Set<String> RECIPIENT_MEMBERS = Set.of("kty", "crv", "x", "y");

    private final StrictJoseJson strictJson;
    private final Sha256Digests digests;
    private final DpopAlgorithmPolicy algorithms;

    public JosePasswordProofVerifier(StrictJoseJson strictJson, Sha256Digests digests) {
        this(strictJson, digests, new DpopAlgorithmPolicy(Set.of("ES256")));
    }

    public JosePasswordProofVerifier(StrictJoseJson strictJson, Sha256Digests digests,
                                      DpopAlgorithmPolicy algorithms) {
        this.strictJson = Objects.requireNonNull(strictJson, "strictJson");
        this.digests = Objects.requireNonNull(digests, "digests");
        this.algorithms = Objects.requireNonNull(algorithms, "algorithms");
    }

    @Override
    public VerifiedPasswordProofs verify(PasswordProofRequest request, StoredDeviceKey deviceKey) {
        try {
            return verifyChecked(request, deviceKey);
        } catch (InvalidCryptographicInputException invalid) {
            throw new InvalidPasswordProofException(invalid);
        }
    }

    private VerifiedPasswordProofs verifyChecked(PasswordProofRequest request,
                                                  StoredDeviceKey deviceKey) {
        Objects.requireNonNull(request, "request");
        PasswordOperationContext operation = request.operation();
        boolean claimedBinding = operation.claimedBindingId() != null;
        if (claimedBinding != (deviceKey != null)
                || claimedBinding != (request.wire().deviceProof() != null)) {
            throw new InvalidCryptographicInputException();
        }

        VerifiedDpopProof dpop = request.wire().dpop();
        JWK requestKey = verifiedRequestKey(dpop);
        ECKey responseKey = recipientKey(request.wire().responsePublicJwk());
        Digest32 responseThumbprint = thumbprint(responseKey);
        String installationHash = digests.sha256(
                operation.deviceId().getBytes(StandardCharsets.UTF_8)).base64Url();

        Digest32 requestProofId = verifyTypedProof(request.wire().requestKeyProof(),
                requestKey, "bank-password-key-proof+jwt", "PASSWORD_LOGIN_KEY_BINDING",
                operation, dpop.requestKey().digest(), responseThumbprint,
                installationHash, request.now(), null);
        Digest32 deviceProofId = null;
        Digest32 deviceThumbprint = null;
        if (claimedBinding) {
            ECKey verifiedDeviceKey = storedDeviceKey(deviceKey);
            deviceThumbprint = deviceKey.thumbprint();
            deviceProofId = verifyTypedProof(request.wire().deviceProof(), verifiedDeviceKey,
                    "bank-password-device-proof+jwt", "PASSWORD_LOGIN_DEVICE_PROOF",
                    operation, dpop.requestKey().digest(), responseThumbprint,
                    installationHash, request.now(), deviceThumbprint);
        }
        return new VerifiedPasswordProofs(dpop.requestKey(), responseThumbprint,
                deviceThumbprint, new PasswordProofIds(dpop.proofIdDigest(), requestProofId,
                deviceProofId), requestKey.toPublicJWK().toJSONString(),
                responseKey.toPublicJWK().toJSONString());
    }

    private JWK verifiedRequestKey(VerifiedDpopProof verified) {
        try {
            JWK key = JWK.parse(verified.publicJwk());
            algorithms.checkPublicKey(key);
            if (!thumbprint(key).equals(verified.requestKey().digest())) {
                throw new InvalidCryptographicInputException();
            }
            return key;
        } catch (ParseException | JOSEException failure) {
            throw new InvalidCryptographicInputException(failure);
        }
    }

    private ECKey recipientKey(String json) {
        strictJson.checkJson(json);
        try {
            if (!RECIPIENT_MEMBERS.equals(JSONObjectUtils.parse(json).keySet())) {
                throw new InvalidCryptographicInputException();
            }
            ECKey key = ECKey.parse(json);
            if (key.isPrivate() || !Curve.P_256.equals(key.getCurve())) {
                throw new InvalidCryptographicInputException();
            }
            return key;
        } catch (ParseException failure) {
            throw new InvalidCryptographicInputException(failure);
        }
    }

    private ECKey storedDeviceKey(StoredDeviceKey stored) {
        try {
            var publicKey = KeyFactory.getInstance("EC")
                    .generatePublic(new X509EncodedKeySpec(stored.publicKeySpki()));
            if (!(publicKey instanceof ECPublicKey ecPublicKey)) {
                throw new InvalidCryptographicInputException();
            }
            ECKey key = new ECKey.Builder(Curve.P_256, ecPublicKey).build();
            if (!thumbprint(key).equals(stored.thumbprint())) {
                throw new InvalidCryptographicInputException();
            }
            return key;
        } catch (GeneralSecurityException failure) {
            throw new InvalidCryptographicInputException(failure);
        }
    }

    private Digest32 verifyTypedProof(String compact, JWK signingKey, String type,
                                      String purpose, PasswordOperationContext operation,
                                      Digest32 requestThumbprint, Digest32 responseThumbprint,
                                      String installationHash, Instant now, Digest32 deviceThumbprint) {
        strictJson.checkCompactJws(compact);
        try {
            SignedJWT proof = SignedJWT.parse(compact);
            var header = proof.getHeader();
            String expectedKid = deviceThumbprint == null
                    ? requestThumbprint.base64Url() : deviceThumbprint.base64Url();
            if (!JWS_HEADERS.equals(header.toJSONObject().keySet())
                    || (deviceThumbprint != null && !JWSAlgorithm.ES256.equals(header.getAlgorithm()))
                    || header.getType() == null || !type.equals(header.getType().toString())
                    || !expectedKid.equals(header.getKeyID())
                    || !proof.verify(deviceThumbprint == null
                            ? new DefaultJWSVerifierFactory().createJWSVerifier(header,
                                    algorithms.publicKey(signingKey, header.getAlgorithm()))
                            : new ECDSAVerifier((ECKey) signingKey))) {
                throw new InvalidCryptographicInputException();
            }
            JWTClaimsSet claims = proof.getJWTClaimsSet();
            Set<String> expectedClaims = deviceThumbprint == null ? KEY_CLAIMS : DEVICE_CLAIMS;
            Instant issuedAt = Objects.requireNonNull(claims.getIssueTime(), "iat").toInstant();
            Instant expiresAt = Objects.requireNonNull(claims.getExpirationTime(), "exp").toInstant();
            if (!expectedClaims.equals(claims.getClaims().keySet())
                    || !Long.valueOf(1).equals(claims.getLongClaim("v"))
                    || !purpose.equals(claims.getStringClaim("purpose"))
                    || !operation.operationId().toString().equals(claims.getStringClaim("operationId"))
                    || !operation.appId().equals(claims.getStringClaim("appId"))
                    || !operation.platform().equals(claims.getStringClaim("platform"))
                    || !installationHash.equals(claims.getStringClaim("installationHash"))
                    || !operation.username().equals(claims.getStringClaim("username"))
                    || !Objects.equals(bindingId(operation), claims.getStringClaim("deviceBindingId"))
                    || !requestThumbprint.base64Url().equals(claims.getStringClaim("requestKeyJkt"))
                    || !responseThumbprint.base64Url().equals(claims.getStringClaim("responseKeyJkt"))
                    || (deviceThumbprint != null && !deviceThumbprint.base64Url()
                            .equals(claims.getStringClaim("deviceKeyJkt")))
                    || claims.getJWTID() == null || claims.getJWTID().isBlank()
                    || now.isBefore(issuedAt.minusSeconds(5)) || !now.isBefore(expiresAt)
                    || !expiresAt.isAfter(issuedAt) || expiresAt.isAfter(issuedAt.plusSeconds(120))) {
                throw new InvalidCryptographicInputException();
            }
            return digests.ofProofId(claims.getJWTID());
        } catch (JOSEException | ParseException | NullPointerException failure) {
            throw new InvalidCryptographicInputException(failure);
        }
    }

    private String bindingId(PasswordOperationContext operation) {
        return operation.claimedBindingId() == null
                ? null : operation.claimedBindingId().toString();
    }

    private Digest32 thumbprint(JWK key) {
        try {
            return Digest32.fromBase64Url(key.computeThumbprint().toString());
        } catch (JOSEException failure) {
            throw new InvalidCryptographicInputException(failure);
        }
    }
}
