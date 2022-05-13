package shared.encryption.codec;

import client.Client;
import server.client.ClientSpec;
import shared.keys.schemes.AsymmetricEncryptionScheme;
import shared.keys.schemes.SymmetricEncryptionScheme;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;

/**
 * {@link Decoder} decodes a message with a given Key.
 */
public class Decoder {
    /**
     * Decodes a message.
     * This method is used by the Client when decoding an incoming message from the {@link server.Server}.
     *
     * @param message the content
     * @param client  {@link Client} object of the client who's decoding the message.
     * @return decoded message as a byte array
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */
    public static byte[] decodeMessage(byte[] message, Client client) throws NoSuchPaddingException,
            NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        switch (client.getEncryptionAlgorithmType()) {
            case SYMMETRIC -> {
                return SymmetricEncryptionScheme.decrypt(client.getEncryptionAlgorithm(), message,
                                                         client.getSymmetricEncryptionKey().toByteArray(),
                                                         client.getKeySize());
            }
            case ASYMMETRIC -> {
                return AsymmetricEncryptionScheme.decrypt(message, client.getServerRSAKey());
            }
            default -> throw new IllegalStateException("Unexpected value: " + client.getEncryptionAlgorithmType());
        }
    }

    /**
     * Decodes a message.
     * This method is used by the Server when decoding an incoming message from a {@link Client}.
     *
     * @param message    the content
     * @param clientSpec {@link ClientSpec} of the client
     * @return decoded message as a byte array
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */
    public static byte[] decodeMessage(byte[] message, ClientSpec clientSpec) throws NoSuchPaddingException,
            NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        switch (clientSpec.getEncryptionAlgorithmType()) {
            case SYMMETRIC -> {
                return SymmetricEncryptionScheme.decrypt(clientSpec.getEncryptionAlgorithm(), message,
                                                         clientSpec.getSymmetricEncryptionKey().toByteArray(),
                                                         clientSpec.getKeySize());
            }
            case ASYMMETRIC -> {
                return AsymmetricEncryptionScheme.decrypt(message, clientSpec.getPublicRSAKey());
            }
            default -> throw new IllegalStateException("Unexpected value: " + clientSpec.getEncryptionAlgorithmType());
        }
    }


    /**
     * Validate a signature.
     *
     * @param data              the data
     * @param hashingAlgorithm  the hashing algorithm
     * @param publicKey         the public key
     * @param providedSignature the provided signature
     * @return <code>true</code> if the signature is valid; false, otherwise.
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws SignatureException
     */
    public static boolean validateSignature(byte[] data, String hashingAlgorithm, PublicKey publicKey,
            byte[] providedSignature) throws
            NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance(hashingAlgorithm);
        signature.initVerify(publicKey);
        signature.update(data);
        return signature.verify(providedSignature);
    }
}
