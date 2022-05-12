package shared.signing;

import client.Client;
import server.client.ClientSpec;
import shared.message.communication.SignedMessage;

import java.security.*;

/**
 * {@link MessageValidator validates a signed {@link SignedMessage }}
 */
public class MessageValidator {

    /**
     * Verifies the signature of a given message.
     * This method is used by the Server to verify the signature of an incoming message.
     *
     * @param signedMessage Provides the message and signature
     * @param clientSpec {@link ClientSpec} of the sender
     * @return Validity of signature
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws SignatureException
     */
    public static boolean validateMessage(SignedMessage signedMessage, ClientSpec clientSpec) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance(clientSpec.getHashingAlgorithm());
        signature.initVerify(clientSpec.getPublicSigningKey());
        signature.update(signedMessage.getEncryptedMessageBytes());
        return signature.verify(signedMessage.getSigningHash());
    }

    /**
     * Verifies the signature of a given message.
     * This method is used by the Client to verify the signature of an incoming message.
     *
     * @param signedMessage Provides the message and signature
     * @param client {@link Client} receiver
     * @return Validity of signature
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws SignatureException
     */
    public static boolean validateMessage(SignedMessage signedMessage, Client client) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance(client.getHashingAlgorithm());
        signature.initVerify(client.getServerSigningKey());
        signature.update(signedMessage.getEncryptedMessageBytes());
        return signature.verify(signedMessage.getSigningHash());
    }
}
