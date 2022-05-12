package shared.message.handshake.client;

import client.Client;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import picocli.CommandLine;
import shared.encryption.validator.EncryptionAlgorithmType;
import shared.keys.schemes.AsymmetricEncryptionScheme;
import shared.keys.schemes.DiffieHellman;
import shared.message.handshake.ClientHello;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;

import static org.junit.jupiter.api.Assertions.assertEquals;

class ClientHelloTest {
    private ClientHello clientHello;
    private KeyPair clientSigningKeys;
    private KeyPair serverSigningKeys;

    @BeforeEach
    void setUp() throws NoSuchAlgorithmException {
        String[] args = "-e AES -k 256 -m SHA-256 -n pa-user --host localhost --port 1337".split(" ");
        Client client = new Client();
        new CommandLine(client).parseArgs(args);
        this.clientSigningKeys = AsymmetricEncryptionScheme.generateKeys(4096);
        this.serverSigningKeys = AsymmetricEncryptionScheme.generateKeys(4096);
        client.setServerSigningKey(this.serverSigningKeys.getPublic());
        client.setSigningKeys(this.clientSigningKeys);
        client.setEncryptionAlgorithmType(EncryptionAlgorithmType.SYMMETRIC);
        this.clientHello = new ClientHello(client);
    }

    @Test
    void TestClientHello() {
        assertEquals(this.clientHello.getName(), "pa-user");
        assertEquals(this.clientHello.getEncryptionAlgorithm(), "AES");
        assertEquals(this.clientHello.getKeySize(), 256);
        assertEquals(this.clientHello.getHashingAlgorithm(), "SHA-256");
        assertEquals(this.clientHello.getEncryptionAlgorithmType(), EncryptionAlgorithmType.SYMMETRIC);
        assertEquals(this.clientHello.getPublicSigningKey(), this.clientSigningKeys.getPublic());

        BigInteger privateKey = DiffieHellman.generatePrivateKey();
        BigInteger publicKey = DiffieHellman.generatePublicKey(privateKey);

        this.clientHello.setPublicDHKey(publicKey);
        assertEquals(this.clientHello.getPublicDHKey(), publicKey);
    }
}