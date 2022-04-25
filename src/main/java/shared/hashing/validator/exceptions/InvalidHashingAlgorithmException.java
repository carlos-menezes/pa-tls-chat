package shared.hashing.validator.exceptions;

import shared.hashing.validator.HashingValidator;

/**
 * Signals that there was an attempt to use an unknown hashing algorithm.
 * The class <code>InvalidHashingAlgorithmException</code> is a subclass of {@link RuntimeException} and will be
 * thrown by {@link HashingValidator}.
 */
public class InvalidHashingAlgorithmException extends RuntimeException {
    public InvalidHashingAlgorithmException(String algorithm) {
        super(String.format("Invalid algorithm (%s) provided", algorithm));
    }
}
