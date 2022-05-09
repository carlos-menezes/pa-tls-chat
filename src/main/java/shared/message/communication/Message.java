package shared.message.communication;

import java.io.Serializable;

/**
 * The <code>Message</code> abstract class represents the common attributes between the
 * {@link ClientMessage} and {@link ServerMessage}.
 */
public abstract class Message implements Serializable {

    private String message;
    private String hash;

    /**
     * Creates a new <code>Message</code> object by specifying its message and corresponding hash.
     *
     * @param message The message to be sent
     */
    public Message(String message) {
        this.message = message;
    }

    /**
     * Method that returns the message to be sent.
     *
     * @return The message to be sent
     */
    public String getMessage() {
        return message;
    }

    //
    public void setMessage(String message) {
        this.message = message;
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
     * Sets the value of {@link #hash}.
     * @param hash value of hash
     */
    public void setHash(String hash) {
        this.hash = hash;
    }


}
