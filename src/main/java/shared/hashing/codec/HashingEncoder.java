package shared.hashing.codec;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * {@link HashingEncoder} hashes a message (of type {@link String}).
 */
public class HashingEncoder {
    /**
     * Create a digest from a message.
     *
     * @param algorithm hashing algorithm
     * @param message   string to hash
     * @return hex representation of the hash
     */
    public static byte[] createDigest(String algorithm, String message) throws NoSuchAlgorithmException {
            MessageDigest messageDigest = MessageDigest.getInstance(algorithm);
            messageDigest.update(message.getBytes(StandardCharsets.UTF_8));
            return messageDigest.digest();
    }

    /**
     * Converts a byte array to a string.
     *
     * @param bytes byte array
     * @return hex representation of <code>bytes</code>
     */
    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
