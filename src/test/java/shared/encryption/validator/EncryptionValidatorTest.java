package shared.encryption.validator;

import org.junit.jupiter.api.Test;
import shared.encryption.validator.exceptions.InvalidEncryptionAlgorithmException;
import shared.encryption.validator.exceptions.InvalidKeySizeException;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class EncryptionValidatorTest {
    private final EncryptionValidator validator = new EncryptionValidator();

    @Test
    void TestInvalidAlgorithm() {
        assertThrows(InvalidEncryptionAlgorithmException.class, () -> validator.validate("INV-ALG-256", 56));
    }

    @Test
    void TestValidAlgorithmValidKeySize() {
        assertDoesNotThrow(() -> validator.validate("AES", 256));
    }

    @Test
    void TestValidAlgorithmInvalidKeySize() {
        assertThrows(InvalidKeySizeException.class, () -> validator.validate("DES", 128));
    }
}