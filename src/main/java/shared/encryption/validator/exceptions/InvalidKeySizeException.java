package shared.encryption.validator.exceptions;

import java.util.List;

public class InvalidKeySizeException extends RuntimeException {
    public InvalidKeySizeException(String algorithm, List<Integer> allowedKeySizes) {
        super(String.format("No supported key sizes found for %s (valid values: %s)", algorithm,
                            allowedKeySizes.toString()));
    }
}
