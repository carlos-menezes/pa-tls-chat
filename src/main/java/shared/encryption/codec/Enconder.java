package shared.encryption.codec;

import client.Client;
import server.client.ClientSpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.*;

/**
 * {@link Enconder} encodes a message with a given Key.
 */
public class Enconder {
    public static byte[] encodeMessage(String message, Client client) throws NoSuchPaddingException,
            NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance(client.getEncryptionAlgorithm());
        switch (client.getEncryptionAlgorithmType()) {
            case SYMMETRIC -> {
                byte[] sharedKeyBytes = client.getSymmetricEncryptionKey().toByteArray();
                byte[] bytes = ByteBuffer.allocate(client.getKeySize() / 8).put(sharedKeyBytes).array();
                SecretKeySpec secretKey = new SecretKeySpec(bytes, client.getEncryptionAlgorithm());
                cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            }
            case ASYMMETRIC -> cipher.init(Cipher.ENCRYPT_MODE, client.getRSAKeys().getPrivate());
        }

        return cipher.doFinal(message.getBytes());
    }

    public static byte[] encodeMessage(String message, ClientSpec clientSpec) throws NoSuchPaddingException,
            NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance(clientSpec.getEncryptionAlgorithm());
        switch (clientSpec.getEncryptionAlgorithmType()) {
            case SYMMETRIC -> {
                byte[] sharedKeyBytes = clientSpec.getSymmetricEncryptionKey().toByteArray();
                byte[] bytes = ByteBuffer.allocate(clientSpec.getKeySize() / 8).put(sharedKeyBytes).array();
                SecretKeySpec secretKey = new SecretKeySpec(bytes, clientSpec.getEncryptionAlgorithm());
                cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            }
            case ASYMMETRIC -> cipher.init(Cipher.ENCRYPT_MODE, clientSpec.getServerRSAKeys().getPrivate());
        }

        return cipher.doFinal(message.getBytes());
    }

    public static byte[] createSignature(String content, String algorithm, PrivateKey privateKey) throws NoSuchAlgorithmException,
            InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance(algorithm.replace("-", "") + "withRSA");
        signature.initSign(privateKey);
        signature.update(content.getBytes());
        return signature.sign();
    }
}
