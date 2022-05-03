package shared.message.communication;

import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.*;

public class ServerClientTest {

    private final String sender = "JohnDoe";
    private final String message = "Hello World";
    private final String hash = "123456789";

    @Test
    @DisplayName("Should be able to extract the message")
    void testGetMessage() {
        Message serverMessage = new ServerMessage(sender, message, hash);
        String message = serverMessage.getMessage();
        assertEquals(message, "Hello World");
    }

    @Test
    @DisplayName("Should be able to get the sender")
    void testGetMultipleClients() {
        Message serverMessage = new ServerMessage(sender, message, hash);
        String senderResult = ((ServerMessage) serverMessage).getSender();
        assertEquals(sender, senderResult);
    }

    @Test
    @DisplayName("Should be able to get the hash value")
    void testGetHash() {
        Message serverMessage = new ServerMessage(sender, message, hash);
        String hashResult = serverMessage.getHash();
        assertEquals(hash, hashResult);
    }
}
