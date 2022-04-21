package shared.encryption.validator;

import shared.encryption.validator.exceptions.InvalidEncryptionAlgorithmException;
import shared.encryption.validator.exceptions.InvalidKeySizeException;

import java.util.List;

public class ThreeDESValidator extends Validatable {
    public ThreeDESValidator() throws InvalidEncryptionAlgorithmException,
            InvalidKeySizeException {
        super("3DES", List.of(168));
    }
}
