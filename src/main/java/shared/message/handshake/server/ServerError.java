package shared.message.handshake.server;

import java.io.Serializable;

public record ServerError(String message) implements Serializable {
    public static String USERNAME_IN_USE = "Username already in use.";

    public String getMessage() {
        return message;
    }
}
