package shared.encryption.validator;

import org.junit.jupiter.api.Test;
import shared.encryption.validator.exceptions.InvalidEncryptionAlgorithmException;
import shared.encryption.validator.exceptions.InvalidKeySizeException;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class EncryptionValidatorTest {
    private EncryptionValidator validator;

    @Test
    void TestInvalidAlgorithm() {
        this.validator = new EncryptionValidator(List.of("INV-ALG-256"), List.of(56));
        assertThrows(InvalidEncryptionAlgorithmException.class, () -> validator.validate());
    }

    @Test
    void TestValidAlgorithmValidKeySize() {
        this.validator = new EncryptionValidator(List.of("AES"), List.of(256));
        assertDoesNotThrow(() -> validator.validate());
    }

    @Test
    void TestValidAlgorithmInvalidKeySize() {
        this.validator = new EncryptionValidator(List.of("DES"), List.of(128));
        assertThrows(InvalidKeySizeException.class, () -> validator.validate());
    }
}