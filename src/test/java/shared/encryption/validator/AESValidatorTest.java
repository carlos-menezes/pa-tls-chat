package shared.encryption.validator;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import shared.encryption.validator.exceptions.InvalidKeySizeException;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class AESValidatorTest {
    private AESValidator validator;

    @BeforeEach
    void setUp() {
        this.validator = new AESValidator();
    }

    @Test
    void TestGetAlgorithmName() {
        assertEquals(this.validator.getName(), "AES");
    }

    @Test
    void TestGetKeySizes() {
        assertEquals(this.validator.getKeySizes(), List.of(128, 192, 256));
    }

    @Test
    void TestGetAlgorithmType() {
        assertEquals(this.validator.getType(), EncryptionAlgorithmType.SYMMETRIC);
    }

    @ParameterizedTest
    @ValueSource(ints = {1, 3, 5, -3, 15, Integer.MAX_VALUE})
    void InvalidKeySizeTest(int n) {
        assertThrows(InvalidKeySizeException.class, () -> this.validator.validate(n));
    }

    @Test
    void ValidKeySizeTest() {
        assertDoesNotThrow(() -> {
            this.validator.validate(128);
            this.validator.validate(192);
            this.validator.validate(256);
        });
    }

}