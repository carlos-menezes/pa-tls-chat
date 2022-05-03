package shared.message.communication;

/**
 * The <code>Message</code> abstract class represents the common attributes between the
 * {@link ClientMessage} and {@link ServerMessage}.
 */
public abstract class Message {

    private final String message;
    private final String hash;

    /**
     * Creates a new <code>Message</code> object by specifying its message and corresponding hash.
     *
     * @param message The message to be sent
     * @param hash The hash of the message, <code>null</code> if the client doesn't support
     *             any hashing algorithm
     */
    public Message(String message, String hash){
        this.message = message;
        this.hash = hash;
    }

    /**
     * Method that returns the message to be sent.
     *
     * @return The message to be sent
     */
    public String getMessage() {
        return message;
    }

    /**
     * Method that returns the hash of the message.
     *
     * @return The hash of the message, <code>null</code> if the client doesn't support
     *         any hashing algorithm
     */
    public String getHash() {
        return hash;
    }

    /**
     * Method that parses a message to a {@link ServerMessage} by specifying the sender
     * and the hash of the message.
     *
     * @param sender Message sender
     * @param hash The hash of the message, <code>null</code> if the client doesn't support
     *             any hashing algorithm
     * @return A new {@link ServerMessage} object
     */
    public ServerMessage parseToServerMessage(String sender, String hash) {
        return new ServerMessage(sender, this.message, hash);
    }
}
