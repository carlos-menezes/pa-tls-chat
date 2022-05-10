package shared.encryption.decoder;

import org.apache.commons.lang3.SerializationUtils;
import shared.encryption.encoder.MessageEncoder;
import shared.message.communication.Message;
import shared.message.communication.SignedMessage;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/**
 * {@link MessageDecoder} decodes a message with a given Key.
 */
public class MessageDecoder {

    /**
     *
     * @param signedMessage {@link SignedMessage} to decode
     * @param key Key
     * @param keySize Size of the key
     * @param encryptionAlgorithm Encryption algorithm used
     * @return Decoded message
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */
    public static Message decodeMessage(SignedMessage signedMessage, BigInteger key, Integer keySize, String encryptionAlgorithm) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Message message = null;
        byte[] sharedKeyBytes = key.toByteArray();
        byte[] bytes = ByteBuffer.allocate(keySize / 8).put(sharedKeyBytes).array();
        SecretKeySpec secretKey = new SecretKeySpec(bytes, encryptionAlgorithm);
        message = SerializationUtils.deserialize(signedMessage.getEncryptedMessageBytes());
        byte[] encryptedMessageBytes = Base64.getDecoder().decode(message.getMessage());
        Cipher decryptCipher = Cipher.getInstance(encryptionAlgorithm);
        decryptCipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decryptedMessageBytes = decryptCipher.doFinal(encryptedMessageBytes);
        message.setMessage(new String(decryptedMessageBytes));
        return message;
    }

    /**
     *
     * @param signedMessage {@link SignedMessage} to decode
     * @param key Key
     * @param encryptionAlgorithm Encryption algorithm used
     * @return Decoded message
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */
    public static Message decodeMessage(SignedMessage signedMessage, Key key, String encryptionAlgorithm) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Message message = null;
        message = SerializationUtils.deserialize(signedMessage.getEncryptedMessageBytes());
        byte[] encryptedMessageBytes = Base64.getDecoder().decode(message.getMessage());
        Cipher decryptCipher = Cipher.getInstance(encryptionAlgorithm);
        decryptCipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decryptedMessageBytes = decryptCipher.doFinal(encryptedMessageBytes);
        message.setMessage(new String(decryptedMessageBytes));
        return message;
    }
}
