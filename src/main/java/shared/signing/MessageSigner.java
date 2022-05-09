package shared.signing;

import shared.message.communication.SignedMessage;

import java.security.*;

/**
 * {@link MessageSigner} signs a message (of type byte[]).
 */
public class MessageSigner {

    /**
     * Signs a given byte array with the specified hashing algorithm using RSA encryption
     *
     * @param hashingAlgorithm Hashing algorithm (e.g.: SHA256withRSA)
     * @param privateKey       Private key to be used
     * @param toSign           Content to be signed
     * @return {@link SignedMessage} object
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws SignatureException
     */
    public static SignedMessage signMessage(String hashingAlgorithm, PrivateKey privateKey, byte[] toSign) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance(hashingAlgorithm.isEmpty() ? "SHA256withRSA" : hashingAlgorithm);
        signature.initSign(privateKey);
        signature.update(toSign);
        byte[] digitalSignature = signature.sign();
        return new SignedMessage(toSign, digitalSignature);
    }

}
