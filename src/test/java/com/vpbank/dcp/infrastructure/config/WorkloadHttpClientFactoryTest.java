package com.vpbank.dcp.infrastructure.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.vpbank.dcp.infrastructure.config.properties.WorkloadTlsProperties;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManagerFactory;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class WorkloadHttpClientFactoryTest {

    @TempDir
    Path temporaryDirectory;

    @Test
    void missingTrustOrIdentityCannotFallBackToPlatformDefault() {
        var properties = new WorkloadTlsProperties("/missing/client.p12", "private-password",
                "/missing/trust.p12", "trust-password", 2000);
        assertThatThrownBy(() -> new WorkloadHttpClientFactory().create(properties))
                .isInstanceOf(InvalidWorkloadTlsConfigurationException.class);
        assertThat(properties.toString()).doesNotContain("private-password", "trust-password");
    }

    @Test
    void explicitPkcs12IdentityAndTrustCreateTlsOnlyClient() throws Exception {
        Path store = temporaryDirectory.resolve("workload-test.p12");
        String keytool = Path.of(System.getProperty("java.home"), "bin", "keytool").toString();
        Process process = new ProcessBuilder(keytool, "-genkeypair", "-alias", "test-workload",
                "-keyalg", "EC", "-groupname", "secp256r1", "-dname", "CN=localhost",
                "-ext", "SAN=dns:localhost",
                "-storetype", "PKCS12", "-keystore", store.toString(),
                "-storepass", "test-only-password", "-keypass", "test-only-password",
                "-validity", "1", "-noprompt").redirectErrorStream(true).start();
        String output = new String(process.getInputStream().readAllBytes());
        assertThat(process.waitFor()).withFailMessage(output).isZero();

        var properties = new WorkloadTlsProperties(store.toString(), "test-only-password",
                store.toString(), "test-only-password", 1200);
        HttpClient client = new WorkloadHttpClientFactory().create(properties);
        assertThat(client.connectTimeout()).contains(java.time.Duration.ofMillis(1200));
        assertThat(client.sslParameters().getProtocols()).containsExactly("TLSv1.3");
        assertThat(client.sslParameters().getEndpointIdentificationAlgorithm()).isEqualTo("HTTPS");

        var server = startMutualTlsServer(store);
        try {
            URI address = URI.create("https://localhost:" + server.getAddress().getPort() + "/health");
            var request = HttpRequest.newBuilder(address).GET().build();
            assertThat(client.send(request, HttpResponse.BodyHandlers.ofString()).statusCode())
                    .isEqualTo(200);
        } finally {
            server.stop(0);
        }
    }

    private HttpsServer startMutualTlsServer(Path store) throws Exception {
        KeyStore keys = KeyStore.getInstance("PKCS12");
        try (var input = Files.newInputStream(store)) {
            keys.load(input, "test-only-password".toCharArray());
        }
        KeyManagerFactory keyManagers = KeyManagerFactory.getInstance(
                KeyManagerFactory.getDefaultAlgorithm());
        keyManagers.init(keys, "test-only-password".toCharArray());
        TrustManagerFactory trustManagers = TrustManagerFactory.getInstance(
                TrustManagerFactory.getDefaultAlgorithm());
        trustManagers.init(keys);
        SSLContext context = SSLContext.getInstance("TLSv1.3");
        context.init(keyManagers.getKeyManagers(), trustManagers.getTrustManagers(), null);

        HttpsServer server = HttpsServer.create(new InetSocketAddress("localhost", 0), 0);
        server.setHttpsConfigurator(new HttpsConfigurator(context) {
            @Override
            public void configure(com.sun.net.httpserver.HttpsParameters parameters) {
                SSLParameters ssl = context.getDefaultSSLParameters();
                ssl.setProtocols(new String[] {"TLSv1.3"});
                ssl.setNeedClientAuth(true);
                parameters.setSSLParameters(ssl);
            }
        });
        server.createContext("/health", exchange -> {
            exchange.sendResponseHeaders(200, -1);
            exchange.close();
        });
        server.start();
        return server;
    }
}
