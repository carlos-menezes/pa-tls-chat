package shared.encryption.validator;

import shared.encryption.validator.exceptions.InvalidEncryptionAlgorithmException;
import shared.encryption.validator.exceptions.InvalidKeySizeException;

import java.util.List;

public class RSAValidator extends Validatable {
    public RSAValidator() throws InvalidEncryptionAlgorithmException,
            InvalidKeySizeException {
        super("RSA", List.of(1024, 2048, 4096));
    }
}
