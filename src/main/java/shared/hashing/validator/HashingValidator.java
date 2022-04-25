package shared.hashing.validator;

import shared.hashing.validator.exceptions.InvalidHashingAlgorithmException;

import java.util.List;

public class HashingValidator {
    private final List<String> supportedAlgorithms;
    public static final List<String> validAlgorithms = List.of("MD4", "MD5", "SHA-256", "SHA-512");

    public HashingValidator(List<String> supportedAlgorithms) {
        this.supportedAlgorithms = supportedAlgorithms;
    }

    public void validate() throws InvalidHashingAlgorithmException {
        for (String algorithm : supportedAlgorithms) {
            if (!validAlgorithms.contains(algorithm)) {
                throw new InvalidHashingAlgorithmException(algorithm);
            }
        }
    }


}
