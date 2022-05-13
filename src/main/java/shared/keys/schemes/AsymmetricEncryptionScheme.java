package shared.keys.schemes;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;

/**
 * {@link AsymmetricEncryptionScheme} implements static methods for encrypting and decrypting byte arrays using
 * asymmetric encryption algorithms (namely RSA).
 */
public class AsymmetricEncryptionScheme {
    public static KeyPair generateKeys(Integer keySize) throws NoSuchAlgorithmException {
        SecureRandom secureRandom = new SecureRandom();
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(keySize, secureRandom);
        return keyPairGenerator.generateKeyPair();
    }

    /**
     * Encrypt a byte array.
     *
     * @param content content
     * @param key     key
     * @return encrypted byte array
     */
    public static byte[] encrypt(byte[] content, Key key) {
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            return cipher.doFinal(content);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Decrypt a byte array.
     *
     * @param content content
     * @param key     key
     * @return decrypted by array
     */
    public static byte[] decrypt(byte[] content, Key key) {
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, key);
            return cipher.doFinal(content);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
        }
        return null;
    }
}
