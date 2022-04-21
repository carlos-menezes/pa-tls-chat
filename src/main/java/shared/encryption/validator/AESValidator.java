package shared.encryption.validator;

import shared.encryption.validator.exceptions.InvalidEncryptionAlgorithmException;
import shared.encryption.validator.exceptions.InvalidKeySizeException;

import java.util.List;

public class AESValidator extends Validatable {
    public AESValidator() throws InvalidEncryptionAlgorithmException,
            InvalidKeySizeException {
        super("AES", List.of(128, 192, 256));
    }
}
