package shared.message.communication;

/**
 * The <code>ServerMessage</code> class represents a message sent from the server to the client.
 * Extends {@link Message}.
 */
public class ServerUserStatusMessage extends Message {

    /**
     * Creates a new <code>ServerUserStatusMessage</code> object by specifying the message itself.
     *
     * @param message The message to be sent.
     */
    public ServerUserStatusMessage(String message) {
        super(message);
    }
}
