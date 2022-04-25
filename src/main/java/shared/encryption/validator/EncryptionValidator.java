package shared.encryption.validator;

import shared.encryption.validator.exceptions.InvalidEncryptionAlgorithmException;
import shared.encryption.validator.exceptions.InvalidKeySizeException;

import java.util.HashMap;
import java.util.List;

public class EncryptionValidator {
    private final List<String> supportedAlgorithms;
    private final List<Integer> supportedKeySizes;

    private final HashMap<String, Validatable> validators;

    public EncryptionValidator(List<String> supportedAlgorithms, List<Integer> supportedKeySizes) throws
            InvalidEncryptionAlgorithmException, InvalidKeySizeException {
        this.supportedAlgorithms = supportedAlgorithms;
        this.supportedKeySizes = supportedKeySizes;

        this.validators = new HashMap<>();
        this.populateValidators();
    }

    private void populateValidators() {
        this.validators.put("DES", new DESValidator());
        this.validators.put("AES", new AESValidator());
        this.validators.put("RSA", new RSAValidator());
        this.validators.put("3DES", new ThreeDESValidator());
    }

    public void validate() throws InvalidEncryptionAlgorithmException, InvalidKeySizeException {
        for (String algorithm : supportedAlgorithms) {
            if (!this.validators.containsKey(algorithm)) {
                throw new InvalidEncryptionAlgorithmException(algorithm);
            }
            validators.get(algorithm).validate(this.supportedKeySizes);
        }
    }


}
