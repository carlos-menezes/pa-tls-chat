package shared.encryption.validator;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import shared.encryption.validator.exceptions.InvalidKeySizeException;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

class TDESValidatorTest {
    private TDESValidator validator;

    @BeforeEach
    void setUp() {
        this.validator = new TDESValidator();
    }

    // Ideally a parameterized test with every possible combination, but arrays as sources for parameterized tests
    // are funky
    @Test
    void InvalidKeySizeTest() {
        List<Integer> keySizes = List.of(56);
        assertThrows(InvalidKeySizeException.class, () -> this.validator.validate(keySizes));
    }

    @Test
    void ValidKeySizeTest() {
        List<Integer> keySizes = List.of(168);
        assertDoesNotThrow(() -> this.validator.validate(keySizes));
    }

    @Test
    void ValidAndInvalidKeySizeTest() {
        List<Integer> keySizes = List.of(168, 56);
        assertDoesNotThrow(() -> this.validator.validate(keySizes));
    }
}