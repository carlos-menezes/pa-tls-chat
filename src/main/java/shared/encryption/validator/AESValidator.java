package shared.encryption.validator;

import java.util.List;

public class AESValidator extends Validatable {
    public AESValidator() {
        super("AES", List.of(128, 192, 256));
    }
}
