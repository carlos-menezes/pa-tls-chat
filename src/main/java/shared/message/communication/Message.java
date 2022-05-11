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

    /**
     * Method that sets the message
     *
     * @param message Message
     */
    public void setMessage(String message) {
        this.message = message;
    }

}
