package shared.encryption.validator;

import java.util.List;

/**
 * {@link AESValidator} extends {@link Validatable} with the algorithm's name and supported key sizes.
 */
public class AESValidator extends Validatable {
    /**
     * Constructs a new {@link AESValidator} object.
     */
    public AESValidator() {
        super("AES", List.of(128, 192, 256), EncryptionAlgorithmType.SYMMETRIC);
    }
}
