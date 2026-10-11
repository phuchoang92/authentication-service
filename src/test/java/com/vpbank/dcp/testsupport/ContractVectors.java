package com.vpbank.dcp.testsupport;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

public final class ContractVectors {

    private static final Path PATH = Path.of("../docs/DD/target/reference/crypto-vectors.json");
    private static final Path SOFTWARE_KEYS =
            Path.of("../docs/DD/target/reference/software-key-vectors.json");
    private static final Path PASSWORD_ONE_SHOT =
            Path.of("../docs/DD/target/reference/password-one-shot-vectors.json");

    private ContractVectors() {
    }

    public static JsonNode load() throws IOException {
        if (!Files.isRegularFile(PATH)) {
            throw new IllegalStateException("Shared crypto vectors are unavailable");
        }
        return new JsonMapper().readTree(Files.readString(PATH));
    }

    public static JsonNode loadSoftwareKeys() throws IOException {
        if (!Files.isRegularFile(SOFTWARE_KEYS)) {
            throw new IllegalStateException("Software-key vectors are unavailable");
        }
        return new JsonMapper().readTree(Files.readString(SOFTWARE_KEYS));
    }

    public static JsonNode loadPasswordOneShot() throws IOException {
        if (!Files.isRegularFile(PASSWORD_ONE_SHOT)) {
            throw new IllegalStateException("Password one-shot vectors are unavailable");
        }
        return new JsonMapper().readTree(Files.readString(PASSWORD_ONE_SHOT));
    }
}
