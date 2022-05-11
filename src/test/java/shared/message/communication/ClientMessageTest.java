package shared.message.communication;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class ClientMessageTest {

    private final String messageMultipleUsers = "@user1,@user2,@user3 Hello World";
    private final String messageSingleUser = "@user1 Hello World";
    private final String messageBroadcast = "Hello World";

    @Test
    @DisplayName("Should be able to extract the message")
    void testGetMessage() {
        Message clientMessage = new ClientMessage(messageMultipleUsers);
        String message = clientMessage.getMessage();
        assertEquals(message, "Hello World");
    }

    @Test
    @DisplayName("Should be able to get all the clients")
    void testGetMultipleClients() {
        ClientMessage clientMessage = new ClientMessage(messageMultipleUsers);
        HashSet<String> users = clientMessage.getUsers();
        HashSet<String> expectedUsers = new HashSet<>(Arrays.asList("user1", "user2", "user3"));
        assertEquals(users, expectedUsers);
    }

    @Test
    @DisplayName("Should be able to get client if there is only one client")
    void testGetOneClient() {
        ClientMessage clientMessage = new ClientMessage(messageSingleUser);
        HashSet<String> user = clientMessage.getUsers();
        HashSet<String> expectedUser = new HashSet<>(Collections.singletonList("user1"));
        assertEquals(user, expectedUser);
    }

    @Test
    @DisplayName("Should be able to detect if it's a broadcast message")
    void testBroadcast() {
        ClientMessage clientMessage = new ClientMessage(messageBroadcast);
        HashSet<String> broadcast = clientMessage.getUsers();
        HashSet<String> expectedResult = new HashSet<>();
        assertEquals(broadcast, expectedResult);
    }
}
