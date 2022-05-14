package shared.message.handshake.client;

import client.Client;
import org.junit.jupiter.api.Test;
import picocli.CommandLine;
import shared.encryption.validator.EncryptionAlgorithmType;
import shared.keys.schemes.AsymmetricEncryptionScheme;
import shared.keys.schemes.DiffieHellman;
import shared.message.handshake.ClientHello;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;

import static org.junit.jupiter.api.Assertions.*;

class ClientHelloTest {
    @Test
    void TestClientHelloSymmetric() throws NoSuchAlgorithmException {
        String[] args = "-e AES -k 256 -m SHA-256 -n pa-user --host localhost --port 1337".split(" ");
        Client client = new Client();
        new CommandLine(client).parseArgs(args);
        KeyPair clientSigningKeys = AsymmetricEncryptionScheme.generateKeys(4096);
        KeyPair serverSigningKeys = AsymmetricEncryptionScheme.generateKeys(4096);
        client.setServerSigningKey(serverSigningKeys.getPublic());
        client.setSigningKeys(clientSigningKeys);
        client.setEncryptionAlgorithmType(EncryptionAlgorithmType.SYMMETRIC);
        ClientHello clientHello = new ClientHello(client);

        assertEquals(clientHello.getName(), "pa-user");
        assertEquals(clientHello.getEncryptionAlgorithm(), "AES");
        assertEquals(clientHello.getKeySize(), 256);
        assertEquals(clientHello.getHashingAlgorithm(), "SHA-256");
        assertEquals(clientHello.getEncryptionAlgorithmType(), EncryptionAlgorithmType.SYMMETRIC);
        assertEquals(clientHello.getPublicSigningKey(), clientSigningKeys.getPublic());

        BigInteger privateKey = DiffieHellman.generatePrivateKey();
        BigInteger publicKey = DiffieHellman.generatePublicKey(privateKey);

        clientHello.setPublicDiffieHellmanKey(publicKey);
        assertEquals(clientHello.getPublicDiffieHellmanKey(), publicKey);
    }

    @Test
    void TestClientHelloAsymmetric() throws NoSuchAlgorithmException {
        String[] args = "-e RSA -k 1024 -m SHA-512 -n pa-user --host localhost --port 1337".split(" ");
        Client client = new Client();
        new CommandLine(client).parseArgs(args);
        KeyPair clientSigningKeys = AsymmetricEncryptionScheme.generateKeys(4096);
        KeyPair clientRSAKeys = AsymmetricEncryptionScheme.generateKeys(1024);
        KeyPair serverSigningKeys = AsymmetricEncryptionScheme.generateKeys(4096);
        client.setServerSigningKey(serverSigningKeys.getPublic());
        client.setSigningKeys(clientSigningKeys);
        client.setEncryptionAlgorithmType(EncryptionAlgorithmType.ASYMMETRIC);
        client.setRSAKeys(clientRSAKeys);
        ClientHello clientHello = new ClientHello(client);

        assertEquals(clientHello.getName(), "pa-user");
        assertNotNull(clientHello.getPublicRSAKey());
        assertEquals(clientHello.getEncryptionAlgorithm(), "RSA");
        assertEquals(clientHello.getKeySize(), 1024);
        assertEquals(clientHello.getHashingAlgorithm(), "SHA-512");
        assertEquals(clientHello.getEncryptionAlgorithmType(), EncryptionAlgorithmType.ASYMMETRIC);
        assertEquals(clientHello.getPublicSigningKey(), clientSigningKeys.getPublic());
        assertEquals(clientHello.getPublicRSAKey(), clientRSAKeys.getPublic());


        BigInteger privateKey = DiffieHellman.generatePrivateKey();
        BigInteger publicKey = DiffieHellman.generatePublicKey(privateKey);

        clientHello.setPublicDiffieHellmanKey(publicKey);
        assertEquals(clientHello.getPublicDiffieHellmanKey(), publicKey);
    }
}