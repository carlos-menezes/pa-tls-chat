package shared.encryption.validator;

import java.util.List;

/**
 * {@link DESValidator} extends {@link Validatable} with the algorithm's name and supported key sizes.
 */
public class DESValidator extends Validatable {
    /**
     * Constructs a new {@link DESValidator} object.
     */
    public DESValidator() {
        super("DES", List.of(56), EncryptionAlgorithmType.SYMMETRIC);
    }
}
