package shared.logging;

/**
 * The <code>Messages</code> class represents the messages that a user entered or left the chat.
 */
public class Messages {
    /**
     * Returns a message that a user joined the chat
     *
     * @param user User that joined the chat
     * @return Message that the user joined the chat
     */
    public static String userJoined(String user) {
        return String.format("@%s joined the chat.", user);
    }

    /**
     * Returns a message that a user left the chat
     *
     * @param user User that left the chat
     * @return Message that the user left the chat
     */
    public static String userLeft(String user) {
        return String.format("@%s left the chat.", user);
    }
}
