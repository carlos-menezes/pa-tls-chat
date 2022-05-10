package shared.encryption.encoder;

import org.apache.commons.lang3.SerializationUtils;
import shared.message.communication.ClientMessage;
import shared.message.communication.Message;
import shared.message.communication.ServerMessage;
import shared.message.communication.SignedMessage;
import shared.signing.MessageSigner;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.*;
import java.util.Base64;

/**
 * {@link MessageEncoder} encodes a message with a given Key.
 */
public class MessageEncoder {

    /**
     * @param message             Message to encrypt ({@link ClientMessage} or {@link ServerMessage})
     * @param encryptionAlgorithm Encryption algorithm to be used
     * @param key                 Key
     * @param keySize             Size of the key
     * @param hashingAlgorithm    Hashing algorithm to be used for authenticity purposes
     * @param signingKey          Signing key for authenticity purposes
     * @return An encrypted {@link SignedMessage}
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */
    public static SignedMessage encodeMessage(Message message, String encryptionAlgorithm, BigInteger key, Integer keySize, String hashingAlgorithm, PrivateKey signingKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, SignatureException {
        byte[] sharedKeyBytes = key.toByteArray();
        byte[] bytes = ByteBuffer.allocate(keySize / 8).put(sharedKeyBytes).array();
        SecretKeySpec secretKey = new SecretKeySpec(bytes, encryptionAlgorithm);
        Cipher cipher = Cipher.getInstance(encryptionAlgorithm);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encodedMessageBytes = cipher.doFinal(message.getMessage().getBytes());
        message.setMessage(Base64.getEncoder().encodeToString(encodedMessageBytes));
        byte[] messageBytes = SerializationUtils.serialize(message);
        SignedMessage signedMessage = MessageSigner.signMessage(hashingAlgorithm, signingKey, messageBytes);
        return signedMessage;
    }

    /**
     * @param message             Message to encrypt ({@link ClientMessage} or {@link ServerMessage})
     * @param encryptionAlgorithm Encryption algorithm to be used
     * @param key                 Key
     * @param hashingAlgorithm    Hashing algorithm to be used for authenticity purposes
     * @param signingKey          Signing key for authenticity purposes
     * @return An encrypted {@link SignedMessage}
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */
    public static SignedMessage encodeMessage(Message message, String encryptionAlgorithm, Key key, String hashingAlgorithm, PrivateKey signingKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, SignatureException {
        Cipher cipher = Cipher.getInstance(encryptionAlgorithm);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encodedMessageBytes = cipher.doFinal(message.getMessage().getBytes());
        message.setMessage(Base64.getEncoder().encodeToString(encodedMessageBytes));
        byte[] messageBytes = SerializationUtils.serialize(message);
        SignedMessage signedMessage = MessageSigner.signMessage(hashingAlgorithm, signingKey, messageBytes);
        return signedMessage;
    }
}
