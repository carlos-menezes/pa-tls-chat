package shared.encryption.validator;

import java.util.List;

public class RSAValidator extends Validatable {
    public RSAValidator() {
        super("RSA", List.of(1024, 2048, 4096));
    }
}
