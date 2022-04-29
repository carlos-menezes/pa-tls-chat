package shared.encryption.algorithms;

import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.*;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

class RSATest {

    @Test
    @DisplayName("Should be able to create a new RSA object")
    void testCreateRSAObject() {
        assertDoesNotThrow(() -> {
            RSA rsa = new RSA();
        });
    }

    @Test
    @DisplayName("Should be able to get the public key")
    void testGetPublicKey() throws NoSuchAlgorithmException {
        RSA rsa = new RSA();
        assertNotNull(rsa.getPublicKey());
    }

    @Test
    @DisplayName("Should be able to encrypt and decrypt a message")
    void testEncryptDecrypt() throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        RSA rsa = new RSA();
        byte[] message = {'h', 'e', 'l', 'l','o'};
        byte[] encryptedMessage= rsa.encrypt(message, rsa.getPublicKey());
        byte[] decryptedMessage = rsa.decrypt(encryptedMessage);
        assertEquals(Arrays.toString(decryptedMessage), Arrays.toString(message));
    }
}
