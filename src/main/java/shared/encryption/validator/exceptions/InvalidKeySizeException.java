package shared.encryption.validator.exceptions;

import shared.encryption.validator.EncryptionValidator;

import java.util.List;

/**
 * Signals that there are no supported key sizes for encryption algorithms.
 * The class <code>InvalidKeySizeException</code> is a subclass of {@link RuntimeException} and will be
 * thrown by {@link EncryptionValidator}.
 */
public class InvalidKeySizeException extends RuntimeException {
    public InvalidKeySizeException(String algorithm, List<Integer> allowedKeySizes) {
        super(String.format("No supported key sizes found for algorithm %s (valid values: %s)", algorithm,
                            allowedKeySizes.toString()));
    }
}
