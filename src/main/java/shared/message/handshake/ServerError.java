package shared.message.handshake;

import java.io.Serializable;

/**
 * The <code>ServerError</code> class represents an error message from the server in
 * the handshake protocol.
 */
public record ServerError(String message) implements Serializable {
    public static String USERNAME_IN_USE = "Username already in use.";
}
