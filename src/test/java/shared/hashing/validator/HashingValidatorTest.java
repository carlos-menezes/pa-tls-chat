package shared.hashing.validator;

import org.junit.jupiter.api.Test;
import shared.hashing.validator.exceptions.InvalidHashingAlgorithmException;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class HashingValidatorTest {
    private final HashingValidator validator = new HashingValidator();

    @Test
    void TestValidAlgorithms() {
        assertDoesNotThrow(() -> {
            this.validator.validate("SHA-256");
            this.validator.validate("SHA-512");
            this.validator.validate("MD4");
            this.validator.validate("MD5");
        });
    }

    @Test
    void TestInvalidAlgorithms() {
        assertThrows(InvalidHashingAlgorithmException.class, () -> this.validator.validate("COL-420"));
    }
}