package shared.encryption.validator;

import java.util.List;

/**
 * {@link TripleDESValidator} extends {@link Validatable} with the algorithm's name and supported key sizes.
 */
public class TripleDESValidator extends Validatable {
    /**
     * Constructs a new {@link TripleDESValidator} object.
     */
    public TripleDESValidator() {
        super("TripleDES", List.of(192), EncryptionAlgorithmType.SYMMETRIC);
    }
}
