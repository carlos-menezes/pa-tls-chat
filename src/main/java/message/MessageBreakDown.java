package message;

import java.util.ArrayList;
import java.util.Collections;

/**
 * The <code>MessageBreakDown</code> class represents all the operations executed in a message sent from a client.
 * Extracts an <code>array</code> of user that the message is going to be sent to and extracts the message itself.
 */
public class MessageBreakDown {
    private static final String USER_DECORATOR = "@";
    private static final String WORD_DELIMITER = " ";
    private static final String USER_DELIMITER = ",";

    /**
     * This class has a private constructor so that it cannot be initialized
     */
    private MessageBreakDown() {}

    /**
     * Method that returns all the users that the message is going to be sent to.
     * The message is separated and the users are extract using their decorators (@)
     *
     * @param originalMessage Original message sent from the client.
     * @return <code>ArrayList</code> of all the users that the message is going to be sent to.
     */
    public static ArrayList<String> getUsers(String originalMessage) {
        // If the there is no user specified in the message it's going to be a broadcast
        if(!originalMessage.startsWith(USER_DECORATOR))
            return new ArrayList<>(Collections.singletonList("broadcast"));

        // Users with delimiter and decorator
        String splitMessage = originalMessage.split(WORD_DELIMITER)[0];
        // Users with the decorators
        String[] usersWithDecorator = splitMessage.split(USER_DELIMITER);
        ArrayList<String> users = new ArrayList<>();
        // Remove all the decorators
        for(String user: usersWithDecorator)
            users.add(user.substring(1));

        return users;
    }

    /**
     * Method returns the message that is going to be sent to other clients.
     * This message is extracted from the original text that the sender wrote.
     * Removes users from string.
     *
     * @param originalMessage Original message sent from the client.
     * @return The message that is going to be sent to the other clients
     */
    public static String getMessage(String originalMessage) {
        // Message to be returned
        StringBuilder message = new StringBuilder();
        String[] splitMessage = originalMessage.split(WORD_DELIMITER);

        for (String e: splitMessage)
            // Append to the resulting message if it's not the users
            if(!e.startsWith(USER_DECORATOR))
                message.append(e).append(e.equals(splitMessage[splitMessage.length - 1]) ? "" : WORD_DELIMITER);

        return message.toString();
    }
}