package shared.encryption.validator;

import shared.encryption.validator.exceptions.InvalidEncryptionAlgorithmException;
import shared.encryption.validator.exceptions.InvalidKeySizeException;

import java.util.HashMap;

/**
 * {@link EncryptionValidator} offers a streamlined way of verifying if an algorithm's name is valid and if the
 * client's key size is supported by the encryption algorithm.
 */
public class EncryptionValidator {
    private final HashMap<String, Validatable> validators;

    /**
     * Constructs a new {@link EncryptionValidator}.
     */
    public EncryptionValidator() throws InvalidEncryptionAlgorithmException,
            InvalidKeySizeException {
        this.validators = new HashMap<>();
        this.populateValidators();
    }

    /**
     * Populates the <code>validators</code> object with encryption algorithm validators (see {@link Validatable}).
     */
    private void populateValidators() {
        this.validators.put("DES", new DESValidator());
        this.validators.put("AES", new AESValidator());
        this.validators.put("RSA", new RSAValidator());
        this.validators.put("TripleDES", new TripleDESValidator());
    }

    /**
     * Validates an algorithm-keySize pair.
     *
     * @param algorithm algorithm's name
     * @param keySize   an integer representing the key size
     */
    public void validate(String algorithm, Integer keySize) {
        if (!this.validators.containsKey(algorithm)) {
            throw new InvalidEncryptionAlgorithmException(algorithm, this.validators.keySet());
        }
        validators.get(algorithm)
                  .validate(keySize);
    }

    /**
     * Gets the validators.
     *
     * @return value of {{@link #validators}}
     */
    public HashMap<String, Validatable> getValidators() {
        return validators;
    }
}
