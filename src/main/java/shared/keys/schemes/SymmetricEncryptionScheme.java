package shared.keys.schemes;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * {@link SymmetricEncryptionScheme} implements static methods for encrypting and decrypting byte arrays using
 * symmetric encryption algorithms (namely: DES, ThreeDES or AES).
 */
public class SymmetricEncryptionScheme {
    /**
     * Encrypt a byte array.
     *
     * @param algorithm encryption algorithm
     * @param content content
     * @param secretKey secret key
     * @param keySize size of secret key
     * @return encrypted <code>content</code>
     */
    public static byte[] encrypt(String algorithm, byte[] content, SecretKey secretKey, Integer keySize) {
        try {
            byte[] bytes = ByteBuffer.allocate(keySize / 8)
                                     .put((ByteBuffer) secretKey)
                                     .array();
            SecretKeySpec secretKeySpec = new SecretKeySpec(bytes, algorithm);
            Cipher cipher = Cipher.getInstance(algorithm);
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
            return cipher.doFinal(content);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Decrypt a byte array.
     *
     * @param algorithm encryption algorithm
     * @param content content
     * @param secretKey secret key
     * @param keySize size of secret key
     * @return decrypted <code>content</code>
     */
    public static byte[] decrypt(String algorithm, byte[] content, SecretKey secretKey, Integer keySize) {
        try {
            byte[] bytes = ByteBuffer.allocate(keySize / 8)
                                     .put((ByteBuffer) secretKey)
                                     .array();
            SecretKeySpec secretKeySpec = new SecretKeySpec(bytes, algorithm);
            Cipher cipher = Cipher.getInstance(algorithm);
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
            return cipher.doFinal(content);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
        }
        return null;
    }
}
