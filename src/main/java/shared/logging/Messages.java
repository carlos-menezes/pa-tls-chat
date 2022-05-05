package shared.logging;

public class Messages {
    public static String userJoined(String user) {
        return String.format("@%s joined the chat.", user);
    }

    public static String userLeft(String user) {
        return String.format("@%s left the chat.", user);
    }
}
