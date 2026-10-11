package com.vpbank.dcp.infrastructure.config;

import com.vpbank.dcp.infrastructure.config.properties.WorkloadTlsProperties;
import java.io.IOException;
import java.net.http.HttpClient;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.time.Duration;
import java.util.Objects;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManagerFactory;

/** Loads explicit client identity and trust anchors; never falls back to JVM default trust. */
public final class WorkloadHttpClientFactory {

    public HttpClient create(WorkloadTlsProperties properties) {
        Objects.requireNonNull(properties, "properties");
        try {
            char[] keyPassword = properties.keyStorePassword().toCharArray();
            char[] trustPassword = properties.trustStorePassword().toCharArray();
            try {
                KeyStore clientKeys = load(properties.keyStore(), keyPassword);
                KeyStore trustAnchors = load(properties.trustStore(), trustPassword);
                if (!hasPrivateKey(clientKeys) || trustAnchors.size() == 0) {
                    throw new InvalidWorkloadTlsConfigurationException();
                }
                KeyManagerFactory keyManagers = KeyManagerFactory.getInstance(
                        KeyManagerFactory.getDefaultAlgorithm());
                keyManagers.init(clientKeys, keyPassword);
                TrustManagerFactory trustManagers = TrustManagerFactory.getInstance(
                        TrustManagerFactory.getDefaultAlgorithm());
                trustManagers.init(trustAnchors);
                SSLContext context = SSLContext.getInstance("TLSv1.3");
                context.init(keyManagers.getKeyManagers(), trustManagers.getTrustManagers(), null);
                SSLParameters ssl = new SSLParameters();
                ssl.setProtocols(new String[] {"TLSv1.3"});
                ssl.setEndpointIdentificationAlgorithm("HTTPS");
                return HttpClient.newBuilder()
                        .sslContext(context)
                        .sslParameters(ssl)
                        .connectTimeout(Duration.ofMillis(properties.connectTimeoutMs()))
                        .version(HttpClient.Version.HTTP_2)
                        .build();
            } finally {
                java.util.Arrays.fill(keyPassword, '\0');
                java.util.Arrays.fill(trustPassword, '\0');
            }
        } catch (IOException | GeneralSecurityException | IllegalArgumentException failure) {
            throw new InvalidWorkloadTlsConfigurationException(failure);
        }
    }

    private KeyStore load(String file, char[] password) throws IOException, GeneralSecurityException {
        if (file == null || file.isBlank() || password.length == 0) {
            throw new InvalidWorkloadTlsConfigurationException();
        }
        Path path = Path.of(file);
        if (!Files.isRegularFile(path) || !Files.isReadable(path)) {
            throw new InvalidWorkloadTlsConfigurationException();
        }
        KeyStore store = KeyStore.getInstance("PKCS12");
        try (var input = Files.newInputStream(path)) {
            store.load(input, password);
        }
        return store;
    }

    private boolean hasPrivateKey(KeyStore store) throws GeneralSecurityException {
        var aliases = store.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            if (store.isKeyEntry(alias) && store.getCertificateChain(alias) != null) {
                return true;
            }
        }
        return false;
    }
}
