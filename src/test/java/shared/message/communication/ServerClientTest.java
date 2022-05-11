package shared.message.communication;

import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.*;

public class ServerClientTest {

    private final String sender = "JohnDoe";
    private final String message = "Hello World";

    @Test
    @DisplayName("Should be able to extract the message")
    void testGetMessage() {
        ServerMessage serverMessage = new ServerMessage(sender, message);
        serverMessage.setMessage(message);
        String message = serverMessage.getMessage();
        assertEquals(message, "Hello World");
    }

    @Test
    @DisplayName("Should be able to get the sender")
    void testGetMultipleClients() {
        ServerMessage serverMessage = new ServerMessage(sender, message);
        String senderResult = serverMessage.getSender();
        assertEquals(sender, senderResult);
    }
}
