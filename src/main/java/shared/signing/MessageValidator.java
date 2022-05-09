package shared.signing;

import server.client.ClientSpec;
import shared.message.communication.SignedMessage;

import java.security.*;

/**
 * {@link MessageValidator validates a signed {@link SignedMessage }}
 */
public class MessageValidator {

    /**
     * Verifies the signature of a given message
     *
     * @param hashingAlgorithm Hashing algorithm used by the signer
     * @param publicKey Public key used by the signer
     * @param signedMessage Provides the message and signature
     * @return Validity of signature
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws SignatureException
     */
    public static boolean validateMessage(String hashingAlgorithm, PublicKey publicKey, SignedMessage signedMessage) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance(hashingAlgorithm.isEmpty() ? "SHA256withRSA" : hashingAlgorithm);
        signature.initVerify(publicKey);
        signature.update(signedMessage.getEncryptedMessageBytes());
        return signature.verify(signedMessage.getSigningHash());
    }

}
