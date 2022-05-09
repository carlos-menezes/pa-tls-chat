package shared.message.communication;

import java.io.Serializable;

/**
 * A {@link SignedMessage} encapsulates an encrypted message with its calculated hash
 */
public record SignedMessage(byte[] encryptedMessageBytes, byte[] signingHash) implements Serializable {

    /**
     * Method that returns the encrypted message bytes
     *
     * @return The encrypted message bytes
     */
    public byte[] getEncryptedMessageBytes() {
        return encryptedMessageBytes;
    }

    /**
     * Method that returns the signing hash of the encrypted message.
     *
     * @return The hash of the message
     */
    public byte[] getSigningHash() {
        return signingHash;
    }
}
