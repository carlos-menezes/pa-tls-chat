package shared.keys.schemes;

import org.junit.jupiter.api.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;

import static org.junit.jupiter.api.Assertions.*;

class SymmetricEncryptionSchemeTest {
    private final BigInteger clientPrivateKey = DiffieHellman.generatePrivateKey();

    private final BigInteger serverPrivateKey = DiffieHellman.generatePrivateKey();
    private final BigInteger serverPublicKey = DiffieHellman.generatePublicKey(serverPrivateKey);

    private final BigInteger secretKey = DiffieHellman.computePrivateKey(serverPublicKey, clientPrivateKey);

    private final String encryptionAlgorithm = "AES";
    private final Integer keySize = 128;

    @Test
    void testGetSecretKey() {
        assertDoesNotThrow(() -> {
            SecretKeySpec secretKeySpec = SymmetricEncryptionScheme.getSecretKeyFromBytes(this.keySize,
                                                                                          this.secretKey.toByteArray(),
                                                                                          this.encryptionAlgorithm);
            assertEquals(secretKeySpec.getAlgorithm(), this.encryptionAlgorithm);
        });
    }

    @Test
    void testEncrypt() throws IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException,
            NoSuchAlgorithmException, InvalidKeyException {

        byte[] encryptedContent = SymmetricEncryptionScheme.encrypt(this.encryptionAlgorithm,
                                                                    "Hello World".getBytes(StandardCharsets.UTF_8),
                                                                    this.secretKey.toByteArray(), this.keySize);
        assertEquals(16, encryptedContent.length);
    }

    @Test
    void testDecrypt() throws NoSuchAlgorithmException, IllegalBlockSizeException, NoSuchPaddingException,
            BadPaddingException, InvalidKeyException {
        byte[] encryptedContent = SymmetricEncryptionScheme.encrypt(this.encryptionAlgorithm,
                                                                    "Hello World".getBytes(StandardCharsets.UTF_8),
                                                                    this.secretKey.toByteArray(), this.keySize);
        byte[] decryptedContent = SymmetricEncryptionScheme.decrypt(this.encryptionAlgorithm, encryptedContent, this.secretKey.toByteArray(), this.keySize);
        assertArrayEquals(decryptedContent, "Hello World".getBytes(StandardCharsets.UTF_8));
    }
}