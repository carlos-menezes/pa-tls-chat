package shared.hashing.validator;

import shared.hashing.validator.exceptions.InvalidHashingAlgorithmException;
import shared.hashing.validator.exceptions.UnsupportedHashingAlgorithmException;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;

/**
 * {@link HashingValidator} offers a streamlined way of verifying if an algorithm's name is valid and supported by
 * the server.
 */
public class HashingValidator {

    private final List<String> validAlgorithms;

    /**
     * Constructs a new {@link HashingValidator}.
     */
    public HashingValidator() {
        this.validAlgorithms = List.of("MD4", "MD5", "SHA-256", "SHA-512");
    }

    /**
     * Checks whether a given algorithm is valid or not.
     *
     * @param algorithm algorithm's name
     */
    public void validate(String algorithm) throws InvalidHashingAlgorithmException, UnsupportedHashingAlgorithmException {
        if (!this.validAlgorithms.contains(algorithm)) {
            throw new InvalidHashingAlgorithmException(algorithm, validAlgorithms);
        }

        if (!isHashingAlgorithmSupported(algorithm)) {
            throw new UnsupportedHashingAlgorithmException(algorithm);
        }
    }

    /**
     * Checks whether a given algorithm is supported by the JVM.
     * @return true, if it is supporte by the JVM; false, otherwise.
     */
    public static boolean isHashingAlgorithmSupported(String algorithm) {
        try {
            MessageDigest.getInstance(algorithm);
            return true;
        } catch (NoSuchAlgorithmException e) {
            return false;
        }
    }
}
