package shared.message.communication;

/**
 * The <code>ServerMessage</code> class represents a message sent from the server to the client.
 * Extends {@link Message}.
 */
public class ServerMessage extends Message {

    private final String sender;

    /**
     * Creates a new <code>ServerMessage</code> object by specifying the message sender,
     * the hash of the message and the message itself.
     *
     * @param sender The message sender.
     * @param message The message to be sent.
     * @param hash The hash of the message, <code>null</code> if client doesn't support
     *             any hashing algorithm.
     */
    public ServerMessage(String sender, String message, String hash) {
        super(message, hash);
        this.sender = sender;
    }

    /**
     * Method that returns the sender of a message.
     *
     * @return Sender of the message.
     */
    public String getSender() {
        return sender;
    }
}
