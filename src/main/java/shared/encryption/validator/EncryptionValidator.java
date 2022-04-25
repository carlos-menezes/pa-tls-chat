package shared.encryption.validator;

import shared.encryption.validator.exceptions.InvalidEncryptionAlgorithmException;
import shared.encryption.validator.exceptions.InvalidKeySizeException;

import java.util.HashMap;
import java.util.List;

/**
 * {@link EncryptionValidator} offers a streamlined way of verifying if an algorithm's name is valid and supported by
 * the server and if the supported key sizes are supported by any of the supported encryption algorithms.
 */
public class EncryptionValidator {
    private final List<String> supportedAlgorithms;
    private final List<Integer> supportedKeySizes;
    private final HashMap<String, Validatable> validators;

    /**
     * Constructs a new {@link EncryptionValidator}.
     *
     * @param supportedAlgorithms list of the client's supported algorithms
     * @param supportedKeySizes   list of the client's supported key sizes
     */
    public EncryptionValidator(List<String> supportedAlgorithms, List<Integer> supportedKeySizes) {
        this.supportedAlgorithms = supportedAlgorithms;
        this.supportedKeySizes = supportedKeySizes;

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
        this.validators.put("3DES", new TDESValidator());
    }

    /**
     * Verifies if every algorithm is valid and if there is at least one supported key size for each supported algorithm.
     *
     * @throws InvalidEncryptionAlgorithmException if any of the supplied algorithms are invalid
     * @throws InvalidKeySizeException             if for any of the supplied algorithms, no supported key size is found
     */
    public void validate() throws InvalidEncryptionAlgorithmException, InvalidKeySizeException {
        for (String algorithm : supportedAlgorithms) {
            if (!this.validators.containsKey(algorithm)) {
                throw new InvalidEncryptionAlgorithmException(algorithm, this.validators.keySet());
            }
            validators.get(algorithm).validate(this.supportedKeySizes);
        }
    }
}
