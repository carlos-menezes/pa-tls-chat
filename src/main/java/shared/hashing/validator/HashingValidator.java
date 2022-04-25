package shared.hashing.validator;

import shared.hashing.validator.exceptions.InvalidHashingAlgorithmException;

import java.util.List;

/**
 * {@link HashingValidator} offers a streamlined way of verifying if an algorithm's name is valid and supported by
 * the server.
 */
public class HashingValidator {
    private final List<String> supportedAlgorithms;
    private final List<String> validAlgorithms = List.of("MD4", "MD5", "SHA-256", "SHA-512");

    /**
     * Constructs a new {@link HashingValidator}.
     *
     * @param supportedAlgorithms list of the client's supported algorithms
     */
    public HashingValidator(List<String> supportedAlgorithms) {
        this.supportedAlgorithms = supportedAlgorithms;
    }

    /**
     * Verifies if every algorithm is valid.
     * @throws InvalidHashingAlgorithmException if at least one of the supplied algorithms is invalid
     */
    public void validate() throws InvalidHashingAlgorithmException {
        for (String algorithm : supportedAlgorithms) {
            if (!validAlgorithms.contains(algorithm)) {
                throw new InvalidHashingAlgorithmException(algorithm, validAlgorithms);
            }
        }
    }


}
