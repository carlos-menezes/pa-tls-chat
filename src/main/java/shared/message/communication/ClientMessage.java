package shared.message.communication;

import client.Client;
import shared.encryption.codec.Enconder;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.HashSet;

/**
 * The <code>ClientMessage</code> class represents a message sent from a client.
 * Extracts an <code>array</code> of user that the message is going to be sent to and extracts the message itself.
 * Extends {@link Message}.
 */
public class ClientMessage extends Message {
    private static final String USER_DECORATOR = "@";
    private static final String WORD_DELIMITER = " ";
    private static final String USER_DELIMITER = ",";

    private final HashSet<String> users;

    /**
     * Creates a new <code>ClientMessage</code> object by specifying the raw message sent from the client
     * and the hash of the raw message.
     *
     * @param message Raw message sent from the client.
     */
    public ClientMessage(String message, Client client) throws NoSuchPaddingException, IllegalBlockSizeException,
            NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, SignatureException {
        String messageContent = extractMessage(message);

        byte[] encodedMessage = Enconder.encodeMessage(messageContent, client);
        this.setMessage(encodedMessage);

        byte[] signature = Enconder.createSignature(messageContent, client.getHashingAlgorithm(), client.getSigningKeys().getPrivate()); // Sign the message with the signing key
        this.setSignature(signature);

        this.users = extractUsers(message);
    }

    /**
     * Method that returns all the users that the message is going to be sent to.
     * The message is separated and the users are extract using their decorators (@)
     *
     * @param originalMessage Original message sent from the client.
     * @return <code>ArrayList</code> of all the users that the message is going to be sent to.
     */
    private static HashSet<String> extractUsers(String originalMessage) {
        // If the there is no user specified in the message it's going to be a broadcast
        if (!originalMessage.startsWith(USER_DECORATOR)) {
            return new HashSet<>();
        }

        // Users with delimiter and decorator
        String splitMessage = originalMessage.split(WORD_DELIMITER)[0];
        // Users with the decorators
        String[] usersWithDecorator = splitMessage.split(USER_DELIMITER);
        HashSet<String> users = new HashSet<>();
        // Remove all the decorators
        for (String user : usersWithDecorator) {
            users.add(user.substring(1));
        }

        return users;
    }

    /**
     * Method returns the message that is going to be sent to other clients.
     * This message is extracted from the original text that the sender wrote.
     * Removes users from string.
     *
     * @param originalMessage Original message sent from the client.
     * @return The message that is going to be sent to the other clients
     */
    private static String extractMessage(String originalMessage) {
        // Message to be returned
        StringBuilder message = new StringBuilder();
        String[] splitMessage = originalMessage.split(WORD_DELIMITER);

        for (String e : splitMessage)
        // Append to the resulting message if it's not the users
        {
            if (!e.startsWith(USER_DECORATOR)) {
                message.append(e)
                        .append(e.equals(splitMessage[splitMessage.length - 1]) ? "" : WORD_DELIMITER);
            }
        }

        return message.toString();
    }

    /**
     * Method that returns the users that the message is going to be sent to.
     *
     * @return <code>ArrayList</code> of all the users that the message is going to be sent to.
     */
    public HashSet<String> getUsers() {
        return this.users;
    }
}
