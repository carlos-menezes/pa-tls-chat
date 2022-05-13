package shared.keys.schemes;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * {@link SymmetricEncryptionScheme} implements static methods for encrypting and decrypting byte arrays using
 * symmetric encryption algorithms (namely: DES, ThreeDES or AES).
 */
public class SymmetricEncryptionScheme {
    public static SecretKeySpec getSecretKeyFromBytes(Integer keySize, byte[] key, String algorithm) {
        byte[] bytes = ByteBuffer.allocate(keySize / 8)
                                 .put(key)
                                 .array();
        return new SecretKeySpec(bytes, algorithm);
    }

    /**
     * Encrypt a byte array.
     *
     * @param algorithm encryption algorithm
     * @param content   content
     * @param secretKey secret key
     * @param keySize   size of secret key
     * @return encrypted <code>content</code>
     */
    public static byte[] encrypt(String algorithm, byte[] content, byte[] secretKey, Integer keySize) throws
            InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException,
            NoSuchAlgorithmException {
        SecretKeySpec secretKeySpec = getSecretKeyFromBytes(keySize, secretKey, algorithm);
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
        return cipher.doFinal(content);
    }

    /**
     * Decrypt a byte array.
     *
     * @param algorithm encryption algorithm
     * @param content   content
     * @param secretKey secret key
     * @param keySize   size of secret key
     * @return decrypted <code>content</code>
     */
    public static byte[] decrypt(String algorithm, byte[] content, byte[] secretKey, Integer keySize) throws
            InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException,
            NoSuchAlgorithmException {
            byte[] bytes = ByteBuffer.allocate(keySize / 8)
                                     .put(secretKey)
                                     .array();
            SecretKeySpec secretKeySpec = new SecretKeySpec(bytes, algorithm);
            Cipher cipher = Cipher.getInstance(algorithm);
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
            return cipher.doFinal(content);
    }
}
