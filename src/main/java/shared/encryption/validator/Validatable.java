package shared.encryption.validator;

import shared.encryption.validator.exceptions.InvalidKeySizeException;

import java.util.List;

/**
 * {@link Validatable} is an abstract class which must be extended by any specific algorithm validator.
 * It offers a method for validating ({@link #validate(Integer)}) algorithms and key sizes supported by a client.
 */
public abstract class Validatable {
    private final String name;
    private final List<Integer> keySizes;
    private final EncryptionAlgorithmType type;

    /**
     * Construct a new <code>Validatable</code> object.
     *
     * @param name     name of the algorithm
     * @param keySizes keysizes supported by the algorithm
     */
    protected Validatable(String name, List<Integer> keySizes, EncryptionAlgorithmType type) {
        this.name = name;
        this.keySizes = keySizes;
        this.type = type;
    }

    /**
     * Get the algorithm name.
     *
     * @return value of the algorithm name
     */
    public String getName() {
        return name;
    }

    /**
     * Get the key sizes.
     *
     * @return value of the key sizes
     */
    public List<Integer> getKeySizes() {
        return keySizes;
    }

    /**
     * Get the algorithm type.
     *
     * @return value of the algorithm type
     */
    public EncryptionAlgorithmType getType() {
        return type;
    }

    /**
     * Validates if the client's supported key sizes are correct.
     *
     * @param keySize key size supported by the client
     * @throws InvalidKeySizeException if <code>{@link #keySizes}</code> doesn't contain <code>keySize</code>
     */
    protected void validate(Integer keySize) throws InvalidKeySizeException {
        if (!this.keySizes.contains(keySize)) {
            throw new InvalidKeySizeException(this.name, this.keySizes);
        }
    }


}
