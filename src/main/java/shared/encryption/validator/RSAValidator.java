package shared.encryption.validator;

import java.util.List;

/**
 * {@link RSAValidator} extends {@link Validatable} with the algorithm's name and supported key sizes.
 */
public class RSAValidator extends Validatable {
    /**
     * Constructs a new {@link RSAValidator} object.
     */
    public RSAValidator() {
        super("RSA", List.of(1024, 2048, 4096));
    }
}
