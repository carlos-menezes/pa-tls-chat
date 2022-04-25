package shared.encryption.validator;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.ArgumentsProvider;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import shared.encryption.validator.exceptions.InvalidKeySizeException;

import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

class RSAValidatorTest {
    private RSAValidator validator;

    @BeforeEach
    void setUp() {
        this.validator = new RSAValidator();
    }

    @Test
    void InvalidKeySizeTest() {
        List<Integer> keySizes = List.of(56);
        assertThrows(InvalidKeySizeException.class, () -> this.validator.validate(keySizes));
    }

    // Ideally a parameterized test with every possible combination, but arrays as sources for parameterized tests
    // are funky
    @Test
    void ValidKeySizeTest() {
        List<Integer> all = List.of(1024, 2048, 4096);
        List<Integer> some = List.of(1024, 4096);
        List<Integer> one = List.of(1024);
        assertDoesNotThrow(() -> {
            this.validator.validate(all);
            this.validator.validate(some);
            this.validator.validate(one);
        });
    }

    @Test
    void ValidAndInvalidKeySizeTest() {
        List<Integer> keySizes = List.of(128, 2048, 256);
        assertDoesNotThrow(() -> this.validator.validate(keySizes));
    }
}