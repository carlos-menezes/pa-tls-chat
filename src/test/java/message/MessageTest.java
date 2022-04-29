package message;

import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.*;

class MessageTest {

    @Test
    @DisplayName("Should be able to create a new message object")
    void testCreateMessageObject() {
        assertDoesNotThrow(() -> {
            Message msg = new Message("Test Message");
        });
    }

    @Test
    @DisplayName("Should be able to get message content from Message object")
    void testGetMessageContent() {
        Message msg = new Message("Test Message");
        assertEquals(msg.getMessage(), "Test Message");
    }
}
