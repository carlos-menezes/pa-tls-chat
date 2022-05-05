package shared.logging;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class MessagesTest {
    private final String user = "carlos-luis-otavio";

    @Test
    void testUserJoined() {
        String userJoined = Messages.userJoined(user);
        assertEquals(userJoined, String.format("@%s joined the chat.", user));
    }

    @Test
    void testUserLeft() {
        String userLeft = Messages.userLeft(user);
        assertEquals(userLeft, String.format("@%s left the chat.", user));
    }
}