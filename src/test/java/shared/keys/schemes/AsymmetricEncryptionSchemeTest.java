package shared.keys.schemes;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;

import static org.junit.jupiter.api.Assertions.*;

class AsymmetricEncryptionSchemeTest {

    @Test
    void testGenerateKeys() {
        assertDoesNotThrow(() -> {
            AsymmetricEncryptionScheme.generateKeys(1024);
        });
    }

    @Test
    void testEncrypt() throws NoSuchAlgorithmException {
        KeyPair keyPair = AsymmetricEncryptionScheme.generateKeys(1024);
        byte[] encryptedBytes = AsymmetricEncryptionScheme.encrypt("Hello World".getBytes(StandardCharsets.UTF_8), keyPair.getPrivate());
        assert encryptedBytes != null;
        assertEquals(128, encryptedBytes.length);
    }

    @Test
    void testDecrypt() throws NoSuchAlgorithmException {
        KeyPair keyPair = AsymmetricEncryptionScheme.generateKeys(1024);
        byte[] encryptedBytes = AsymmetricEncryptionScheme.encrypt("Hello World".getBytes(StandardCharsets.UTF_8), keyPair.getPrivate());
        byte[] decryptedBytes = AsymmetricEncryptionScheme.decrypt(encryptedBytes, keyPair.getPublic());
        assertArrayEquals(decryptedBytes, "Hello World".getBytes(StandardCharsets.UTF_8));
    }
}