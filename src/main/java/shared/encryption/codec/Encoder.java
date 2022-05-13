package shared.encryption.codec;

import client.Client;
import server.client.ClientSpec;
import shared.keys.schemes.AsymmetricEncryptionScheme;
import shared.keys.schemes.SymmetricEncryptionScheme;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.nio.charset.StandardCharsets;
import java.security.*;

/**
 * {@link Encoder} encodes a message with a given Key.
 */
public class Encoder {
    /**
     * Encodes a message.
     * This method is used by the Client when encoding an outgoing message to the {@link server.Server}.
     *
     * @param message the content
     * @param client  {@link Client} object of the client who's decoding the message.
     * @return encoded message as a byte array
     */
    public static byte[] encodeMessage(String message, Client client) throws IllegalBlockSizeException,
            NoSuchPaddingException, BadPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        switch (client.getEncryptionAlgorithmType()) {
            case SYMMETRIC -> {
                return SymmetricEncryptionScheme.encrypt(client.getEncryptionAlgorithm(),
                                                         message.getBytes(StandardCharsets.UTF_8),
                                                         client.getSymmetricEncryptionKey().toByteArray(),
                                                         client.getKeySize());
            }
            case ASYMMETRIC -> {
                return AsymmetricEncryptionScheme.encrypt(message.getBytes(StandardCharsets.UTF_8),
                                                          client.getRSAKeys().getPrivate());
            }
        }
        return null;
    }

    /**
     * Encodes a message.
     * This method is used by the Server when encoding an outgoing message to the {@link Client}.
     *
     * @param message    the content
     * @param clientSpec {@link ClientSpec} of the receiver
     * @return encoded message as a byte array
     */
    public static byte[] encodeMessage(String message, ClientSpec clientSpec) throws IllegalBlockSizeException,
            NoSuchPaddingException, BadPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        switch (clientSpec.getEncryptionAlgorithmType()) {
            case SYMMETRIC -> {
                return SymmetricEncryptionScheme.encrypt(clientSpec.getEncryptionAlgorithm(),
                                                         message.getBytes(StandardCharsets.UTF_8),
                                                         clientSpec.getSymmetricEncryptionKey().toByteArray(),
                                                         clientSpec.getKeySize());
            }
            case ASYMMETRIC -> {
                return AsymmetricEncryptionScheme.encrypt(message.getBytes(StandardCharsets.UTF_8),
                                                          clientSpec.getServerRSAKeys().getPrivate());
            }
        }
        return null;
    }


    /**
     * Create signature for a given string.
     *
     * @param content          the content
     * @param hashingAlgorithm the hashing algorithm
     * @param privateKey       the private key
     * @return signature of the content as a byte array
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws SignatureException
     */
    public static byte[] createSignature(String content, String hashingAlgorithm, PrivateKey privateKey) throws
            NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance(hashingAlgorithm);
        signature.initSign(privateKey);
        signature.update(content.getBytes(StandardCharsets.UTF_8));
        return signature.sign();
    }
}
