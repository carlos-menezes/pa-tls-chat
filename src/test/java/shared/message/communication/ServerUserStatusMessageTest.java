package shared.message.communication;

import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.*;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class ServerUserStatusMessageTest {

    private final String message = "Hello World";

    @Test
    @DisplayName("Should be able to create a ServerStatusMessage object")
    void testServerStatusMessage() {
        assertDoesNotThrow(() -> {
            ServerUserStatusMessage s = new ServerUserStatusMessage(message);
        });
    }
}
