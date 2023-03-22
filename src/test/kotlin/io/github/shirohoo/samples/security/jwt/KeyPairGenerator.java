package io.github.shirohoo.samples.security.jwt;

import java.io.BufferedWriter;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyPair;
import java.util.Base64;

class KeyPairGenerator {
    void createKeysWithJCA() throws Exception {
        java.security.KeyPairGenerator generator = java.security.KeyPairGenerator.getInstance("RSA");
        generator.initialize(2_048);
        KeyPair keyPair = generator.generateKeyPair();

        save("app.key", keyPair.getPrivate(), "-----BEGIN PRIVATE KEY-----\n", "\n-----END PRIVATE KEY-----\n");
        save("app.pub", keyPair.getPublic(), "-----BEGIN PUBLIC KEY-----\n", "\n-----END PUBLIC KEY-----\n");
    }

    private void save(String fileName, Key key, String start, String end) throws Exception {
        String dir = "src/main/resources/";

        byte[] encoded = key.getEncoded();
        String base64 = Base64.getEncoder().encodeToString(encoded);

        String pem = start + base64 + end;

        try (BufferedWriter writer = Files.newBufferedWriter(Paths.get(dir, fileName))) {
            writer.write(pem);
        }
    }
}
