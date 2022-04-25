package shared.encryption.validator;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import shared.encryption.validator.exceptions.InvalidKeySizeException;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

class AESValidatorTest {
    private AESValidator validator;

    @BeforeEach
    void setUp() {
        this.validator = new AESValidator();
    }

    @Test
    void InvalidKeySizeTest() {
        List<Integer> keySizes = List.of(56, 400, 5985);
        assertThrows(InvalidKeySizeException.class, () -> this.validator.validate(keySizes));
    }

    // Ideally a parameterized test with every possible combination, but arrays as sources for parameterized tests
    // are funky
    @Test
    void ValidKeySizeTest() {
        List<Integer> all = List.of(128, 192, 256);
        List<Integer> some = List.of(128, 256);
        List<Integer> one = List.of(192);
        assertDoesNotThrow(() -> {
            this.validator.validate(all);
            this.validator.validate(some);
            this.validator.validate(one);
        });
    }

    @Test
    void ValidAndInvalidKeySizeTest() {
        List<Integer> keySizes = List.of(128, 56, 256);
        assertDoesNotThrow(() -> this.validator.validate(keySizes));
    }
}