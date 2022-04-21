package shared.encryption.validator;

import java.util.List;

public class DESValidator extends Validatable {
    public DESValidator() {
        super("DES", List.of(56));
    }
}
