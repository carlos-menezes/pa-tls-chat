package shared.encryption.validator;

import java.util.List;

/**
 * {@link TDESValidator} extends {@link Validatable} with the algorithm's name and supported key sizes.
 */
public class TDESValidator extends Validatable {
    /**
     * Constructs a new {@link TDESValidator} object.
     */
    public TDESValidator() {
        super("3DES", List.of(168));
    }
}
