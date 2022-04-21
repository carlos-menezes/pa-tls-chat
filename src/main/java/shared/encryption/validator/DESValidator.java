package shared.encryption.validator;

import shared.encryption.validator.exceptions.InvalidEncryptionAlgorithmException;
import shared.encryption.validator.exceptions.InvalidKeySizeException;

import java.util.List;

public class DESValidator extends Validatable {
    public DESValidator() throws InvalidEncryptionAlgorithmException,
            InvalidKeySizeException {
        super("DES", List.of(56));
    }
}
