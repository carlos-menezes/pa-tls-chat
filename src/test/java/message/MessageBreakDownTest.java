package message;

import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;


class MessageBreakDownTest {

    private final String messageMultipleUsers = "@user1,@user2,@user3 Hello World";
    private final String messageSingleUser = "@user1 Hello World";
    private final String messageBroadcast = "Hello World";

    @Test
    @DisplayName("Should be able to extract the message")
    void testGetMessage() {
        String message = MessageBreakDown.getMessage(messageMultipleUsers);
        assertEquals(message, "Hello World");
    }

    @Test
    @DisplayName("Should be able to get all the clients")
    void testGetMultipleClients() {
        ArrayList<String> users = MessageBreakDown.getUsers(messageMultipleUsers);
        ArrayList<String> expectedUsers = new ArrayList<>(Arrays.asList("user1", "user2", "user3"));
        assertEquals(users, expectedUsers);
    }

    @Test
    @DisplayName("Should be able to get client if there is only one client")
    void testGetOneClient() {
        ArrayList<String> user = MessageBreakDown.getUsers(messageSingleUser);
        ArrayList<String> expectedUser = new ArrayList<>(Collections.singletonList("user1"));
        assertEquals(user, expectedUser);
    }

    @Test
    @DisplayName("Should be able to detect if it's a broadcast message")
    void testBroadcast() {
        ArrayList<String> broadcast = MessageBreakDown.getUsers(messageBroadcast);
        ArrayList<String> expectedResult = new ArrayList<>(Collections.singletonList("broadcast"));
        assertEquals(broadcast, expectedResult);
    }

}
