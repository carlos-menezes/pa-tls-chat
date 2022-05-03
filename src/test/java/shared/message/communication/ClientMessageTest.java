package shared.message.communication;

import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;

public class ClientMessageTest {

    private final String messageMultipleUsers = "@user1,@user2,@user3 Hello World";
    private final String messageSingleUser = "@user1 Hello World";
    private final String messageBroadcast = "Hello World";
    private final String hash = "123456789";

    @Test
    @DisplayName("Should be able to extract the message")
    void testGetMessage() {
        Message clientMessage = new ClientMessage(messageMultipleUsers, hash);
        String message = clientMessage.getMessage();
        assertEquals(message, "Hello World");
    }

    @Test
    @DisplayName("Should be able to get all the clients")
    void testGetMultipleClients() {
        ClientMessage clientMessage = new ClientMessage(messageMultipleUsers, hash);
        ArrayList<String> users = clientMessage.getUsers();
        ArrayList<String> expectedUsers = new ArrayList<>(Arrays.asList("user1", "user2", "user3"));
        assertEquals(users, expectedUsers);
    }

    @Test
    @DisplayName("Should be able to get client if there is only one client")
    void testGetOneClient() {
        ClientMessage clientMessage = new ClientMessage(messageSingleUser, hash);
        ArrayList<String> user = clientMessage.getUsers();
        ArrayList<String> expectedUser = new ArrayList<>(Collections.singletonList("user1"));
        assertEquals(user, expectedUser);
    }

    @Test
    @DisplayName("Should be able to detect if it's a broadcast message")
    void testBroadcast() {
        ClientMessage clientMessage = new ClientMessage(messageBroadcast, hash);
        ArrayList<String> broadcast = clientMessage.getUsers();
        ArrayList<String> expectedResult = new ArrayList<>(Collections.singletonList("broadcast"));
        assertEquals(broadcast, expectedResult);
    }

    @Test
    @DisplayName("Should be able to get the hash value")
    void testGetHash() {
        Message clientMessage = new ClientMessage(messageMultipleUsers, hash);
        String hashResult = clientMessage.getHash();
        assertEquals(hash, hashResult);
    }

    @Test
    @DisplayName("Should be able to parse to ServerMessage")
    void testParseToServerMessage() {
        ClientMessage clientMessage = new ClientMessage(messageSingleUser, hash);
        ServerMessage parsedMessage = clientMessage.parseToServerMessage(clientMessage.getUsers().get(0), hash);
        assertAll(
                () -> assertEquals(clientMessage.getUsers().get(0), parsedMessage.getSender()),
                () -> assertEquals(clientMessage.getMessage(), parsedMessage.getMessage())
        );
    }
}
