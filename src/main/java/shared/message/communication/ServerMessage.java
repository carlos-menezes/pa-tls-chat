package shared.message.communication;

import server.client.ClientSpec;
import shared.encryption.codec.Encoder;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;

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
     * @param sender  The message sender.
     * @param message The message to be sent.
     */
    public ServerMessage(String sender, String message, ClientSpec clientSpec) throws NoSuchPaddingException,
            IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException,
            SignatureException {
        this.sender = sender;

        byte[] encodedMessage = Encoder.encodeMessage(message, clientSpec);
        this.setMessage(encodedMessage);

        byte[] signature = Encoder.createSignature(message, clientSpec.getHashingAlgorithm(),
                                                   clientSpec.getServerSigningKeys().getPrivate());
        this.setSignature(signature);
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
