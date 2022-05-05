package shared.hashing.validator.exceptions;

import shared.hashing.validator.HashingValidator;

import java.util.List;

/**
 * Signals that there was an attempt to use an unsuppoted hashing algorithm (i.e. not supported by the JVM).
 * The class <code>UnsupportedHashingAlgorithmException</code> is a subclass of {@link RuntimeException} and will be
 * thrown by {@link HashingValidator}.
 */
public class UnsupportedHashingAlgorithmException extends RuntimeException {
    public UnsupportedHashingAlgorithmException(String algorithm) {
        super(String.format("%s is not supported by the JVM", algorithm));
    }
}
