package shared.encryption.validator;

import java.util.List;

/**
 * {@link ThreeDESValidator} extends {@link Validatable} with the algorithm's name and supported key sizes.
 */
public class ThreeDESValidator extends Validatable {
    /**
     * Constructs a new {@link ThreeDESValidator} object.
     */
    public ThreeDESValidator() {
        super("ThreeDES", List.of(168), EncryptionAlgorithmType.SYMMETRIC);
    }
}
