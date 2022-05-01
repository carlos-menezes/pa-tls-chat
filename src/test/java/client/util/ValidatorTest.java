package client.util;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class ValidatorTest {
    @Test
    void ValidUsername() {
        assertAll(() -> assertTrue(Validator.validateUsername("carlos-otavio-luis")),
                  () -> assertTrue(Validator.validateUsername("carlos'ç.:;ºªº")));
    }

    @Test
    void InvalidUsername() {
        assertAll(() -> assertFalse(Validator.validateUsername("@carlos")),
                  () -> assertFalse(Validator.validateUsername("carlos,otavio@ luis")));
    }
}