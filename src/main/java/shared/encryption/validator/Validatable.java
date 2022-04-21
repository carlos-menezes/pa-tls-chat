package shared.encryption.validator;

import shared.encryption.validator.exceptions.InvalidKeySizeException;

import java.util.ArrayList;
import java.util.List;

public abstract class Validatable {
    private final String algorithmName;
    private final List<Integer> keySizes;

    protected Validatable(String algorithmName, List<Integer> keySizes) {
        this.algorithmName = algorithmName;
        this.keySizes = keySizes;
    }

    protected void validate(List<Integer> clientSupportedKeySizes) throws InvalidKeySizeException {
        boolean hasSizeChanged = clientSupportedKeySizes.removeAll(this.keySizes);
        if (!hasSizeChanged) {
            throw new InvalidKeySizeException(this.algorithmName, this.keySizes);
        }
    }
}
