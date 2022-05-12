package shared.message.communication;

import java.io.Serializable;

/**
 * The <code>Message</code> abstract class represents the common attributes between the
 * {@link ClientMessage} and {@link ServerMessage}.
 */
public abstract class Message implements Serializable {

    private byte[] message;
    private byte[] signature;

    /**
     * Creates a new <code>Message</code> object.
     */
    public Message() {

    }

    /**
     * Method that returns the message to be sent.
     *
     * @return The message to be sent
     */
    public byte[] getMessage() {
        return message;
    }


    public void setMessage(byte[] message) {
        this.message = message;
    }


    public byte[] getSignature() {
        return signature;
    }

    public void setSignature(byte[] signature) {
        this.signature = signature;
    }
}
