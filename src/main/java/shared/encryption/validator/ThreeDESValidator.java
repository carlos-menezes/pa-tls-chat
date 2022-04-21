package shared.encryption.validator;

import java.util.List;

public class ThreeDESValidator extends Validatable {
    public ThreeDESValidator() {
        super("3DES", List.of(168));
    }
}
