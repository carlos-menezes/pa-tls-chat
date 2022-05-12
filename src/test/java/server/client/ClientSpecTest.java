package server.client;

import org.junit.jupiter.api.Test;
import shared.encryption.validator.EncryptionAlgorithmType;
import shared.keys.schemes.AsymmetricEncryptionScheme;
import shared.keys.schemes.DiffieHellman;

import java.math.BigInteger;
import java.net.Socket;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class ClientSpecTest {

    @Test
    void TestClientSpecAsymmetric() throws NoSuchAlgorithmException {
        KeyPair rsaKeys = AsymmetricEncryptionScheme.generateKeys(1024);
        Socket socket = new Socket();
        ClientSpec clientSpec = new ClientSpec.Builder()
                .withSocket(socket)
                .withEncryptionAlgorithmType(EncryptionAlgorithmType.ASYMMETRIC)
                .withEncryptionAlgorithm("RSA")
                .withKeySize(1024)
                .withPublicRSAKey(rsaKeys.getPublic())
                .withHashingAlgorithm("MD5")
                .build();
        assertEquals(clientSpec.getSocket(), socket);
        assertEquals(clientSpec.getEncryptionAlgorithmType(), EncryptionAlgorithmType.ASYMMETRIC);
        assertEquals(clientSpec.getEncryptionAlgorithm(), "RSA");
        assertEquals(clientSpec.getKeySize(), 1024);
        assertEquals(clientSpec.getPublicRSAKey(), rsaKeys.getPublic());
        assertEquals(clientSpec.getHashingAlgorithm(), "MD5");
    }

    @Test
    void TestClientSpecSymmetric() {
        BigInteger privateSharedDHKey = DiffieHellman.generatePrivateKey();
        Socket socket = new Socket();
        ClientSpec clientSpec = new ClientSpec.Builder()
                .withSocket(socket)
                .withEncryptionAlgorithmType(EncryptionAlgorithmType.SYMMETRIC)
                .withEncryptionAlgorithm("AES")
                .withKeySize(128)
                .withHashingAlgorithm("MD5")
                .withSymmetricEncryptionKey(privateSharedDHKey)
                .build();
        assertEquals(clientSpec.getSocket(), socket);
        assertEquals(clientSpec.getEncryptionAlgorithmType(), EncryptionAlgorithmType.SYMMETRIC);
        assertEquals(clientSpec.getEncryptionAlgorithm(), "AES");
        assertEquals(clientSpec.getKeySize(), 128);
        assertNull(clientSpec.getPublicRSAKey());
        assertEquals(clientSpec.getHashingAlgorithm(), "MD5");
        assertEquals(clientSpec.getSymmetricEncryptionKey(), privateSharedDHKey);
    }
}