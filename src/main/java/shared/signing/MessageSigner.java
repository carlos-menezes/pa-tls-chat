package shared.signing;

import client.Client;
import server.client.ClientSpec;
import shared.message.communication.SignedMessage;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;

/**
 * {@link MessageSigner} signs a message (of type byte[]).
 */
public class MessageSigner {

    /**
     * Signs a given byte array with the specified hashing algorithm using RSA encryption.
     * This method is used by the Server to sign an outgoing message.
     *
     * @param content    content to sign
     * @param clientSpec {@link ClientSpec} of the receiver
     * @return {@link SignedMessage} object
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws SignatureException
     */
    public static SignedMessage signMessage(byte[] content, ClientSpec clientSpec) throws NoSuchAlgorithmException,
            InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance(clientSpec.getHashingAlgorithm());
        signature.initSign(clientSpec.getServerSigningKeys().getPrivate());
        signature.update(content);
        byte[] digitalSignature = signature.sign();
        return new SignedMessage(content, digitalSignature);
    }

    /**
     * Signs a given byte array with the specified hashing algorithm using RSA encryption.
     * This method is used by the Client to sign an outgoing message.
     *
     * @param content content to sign
     * @param client  sender of the message
     * @return {@link SignedMessage} object
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws SignatureException
     */
    public static SignedMessage signMessage(byte[] content, Client client) throws NoSuchAlgorithmException,
            InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance(client.getHashingAlgorithm());
        signature.initSign(client.getSigningKeys().getPrivate());
        signature.update(content);
        byte[] digitalSignature = signature.sign();
        return new SignedMessage(content, digitalSignature);
    }
}
