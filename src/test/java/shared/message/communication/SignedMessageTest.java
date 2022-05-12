package shared.message.communication;

import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.*;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class SignedMessageTest {

    private final String message = "Hello World";
    private final String hash = "S8jslU";

    @Test
    @DisplayName("Should be able get properties from signed message")
    void testSignedMessage() {
        SignedMessage s = new SignedMessage(message.getBytes(), hash.getBytes());
        assertAll(
            () -> assertEquals(Arrays.toString(s.getEncryptedMessageBytes()), Arrays.toString(message.getBytes())),
            () -> assertEquals(Arrays.toString(s.getSigningHash()), Arrays.toString(hash.getBytes()))
        );
    }
}