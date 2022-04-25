package shared.encryption.validator;

import shared.encryption.validator.exceptions.InvalidKeySizeException;

import java.util.ArrayList;
import java.util.List;

/**
 * {@link Validatable} is an abstract class which must be extended by any specific algorithm validator.
 * It offers a method for validating ({@link #validate(List)}) algorithms and key sizes supported by a client.
 */
public abstract class Validatable {
    private final String algorithmName;
    private final List<Integer> keySizes;

    /**
     * Construct a new <code>Validatable</code> object.
     *
     * @param algorithmName name of the algorithm
     * @param keySizes      keysizes supported by the algorithm
     */
    protected Validatable(String algorithmName, List<Integer> keySizes) {
        this.algorithmName = algorithmName;
        this.keySizes = keySizes;
    }

    /**
     * Validates if the client's supported key sizes are correct.
     *
     * @param clientSupportedKeySizes list of key sizes supported by the client
     * @throws InvalidKeySizeException if <code>clientSupportedKeySizes</code> doesn't contain atleast one of the
     *                                 algorithm's supported key sizes
     */
    protected void validate(List<Integer> clientSupportedKeySizes) throws InvalidKeySizeException {
        List<Integer> keySizesClone = new ArrayList<>(List.copyOf(clientSupportedKeySizes));
        boolean hasSizeChanged = keySizesClone.removeAll(this.keySizes);
        if (!hasSizeChanged) {
            throw new InvalidKeySizeException(this.algorithmName, this.keySizes);
        }
    }
}
