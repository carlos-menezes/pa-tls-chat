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
 * {@link Decoder} decodes a message with a given Key.
 */
public class Decoder {
    public static byte[] decodeMessage(byte[] content, Client client) throws NoSuchPaddingException,
            NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance(client.getEncryptionAlgorithm());
        switch (client.getEncryptionAlgorithmType()) {
            case SYMMETRIC -> {
                byte[] sharedKeyBytes = client.getSymmetricEncryptionKey().toByteArray();
                byte[] bytes = ByteBuffer.allocate(client.getKeySize() / 8).put(sharedKeyBytes).array();
                SecretKeySpec secretKey = new SecretKeySpec(bytes, client.getEncryptionAlgorithm());
                cipher.init(Cipher.DECRYPT_MODE, secretKey);
                return cipher.doFinal(content);
            }
            case ASYMMETRIC -> {
                cipher.init(Cipher.DECRYPT_MODE, client.getServerRSAKey());
                return cipher.doFinal(content);
            }
            default -> throw new IllegalStateException("Unexpected value: " + client.getEncryptionAlgorithmType());
        }
    }

    public static byte[] decodeMessage(byte[] content, ClientSpec clientSpec) throws NoSuchPaddingException,
            NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance(clientSpec.getEncryptionAlgorithm());
        switch (clientSpec.getEncryptionAlgorithmType()) {
            case SYMMETRIC -> {
                byte[] sharedKeyBytes = clientSpec.getSymmetricEncryptionKey().toByteArray();
                byte[] bytes = ByteBuffer.allocate(clientSpec.getKeySize() / 8).put(sharedKeyBytes).array();
                SecretKeySpec secretKey = new SecretKeySpec(bytes, clientSpec.getEncryptionAlgorithm());
                cipher.init(Cipher.DECRYPT_MODE, secretKey);
                return cipher.doFinal(content);
            }
            case ASYMMETRIC -> {
                cipher.init(Cipher.DECRYPT_MODE, clientSpec.getPublicRSAKey());
                return cipher.doFinal(content);
            }
            default -> throw new IllegalStateException("Unexpected value: " + clientSpec.getEncryptionAlgorithmType());
        }
    }

    public static boolean validateSignature(byte[] data, String algorithm, PublicKey publicKey, byte[] providedSignature) throws
            NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance(algorithm.replace("-", "") + "withRSA");
        signature.initVerify(publicKey);
        signature.update(data);
        return signature.verify(providedSignature);
    }
}
