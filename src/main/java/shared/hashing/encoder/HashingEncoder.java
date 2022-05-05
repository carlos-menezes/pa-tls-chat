package shared.hashing.encoder;

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
    public static String createDigest(String algorithm, String message) {
        try {
            MessageDigest messageDigest = MessageDigest.getInstance(algorithm);
            byte[] encoded = messageDigest.digest(message.getBytes(StandardCharsets.UTF_8));
            return bytesToHex(encoded);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        return null;
    }

    /**
     * Converts a byte array to a string.
     *
     * @param bytes byte array
     * @return hex representation of <code>bytes</code>
     */
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

}
