package shared.encryption.validator.exceptions;

import shared.encryption.validator.EncryptionValidator;

import java.util.Set;

/**
 * Signals that there was an attempt to use an unknown encryption algorithm.
 * The class <code>InvalidEncryptionAlgorithmException</code> is a subclass of {@link RuntimeException} and will be
 * thrown by {@link EncryptionValidator}.
 */
public class InvalidEncryptionAlgorithmException extends RuntimeException {
    public InvalidEncryptionAlgorithmException(String algorithm, Set<String> validValues) {
        super(String.format("Invalid encryption algorithm (%s) provided (valid values: %s)", algorithm, validValues));
    }
}
