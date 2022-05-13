package shared.message.communication;

import client.Client;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import picocli.CommandLine;
import shared.encryption.codec.Encoder;
import shared.encryption.validator.EncryptionAlgorithmType;
import shared.keys.schemes.AsymmetricEncryptionScheme;
import shared.keys.schemes.DiffieHellman;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class ClientMessageTest {

    private final String messageMultipleUsers = "@user1,@user2,@user3 Hello World";
    private final String messageBroadcast = "Hello World";
    private Client client;

    @BeforeEach
    void setUp() throws NoSuchAlgorithmException {
        String[] args = "-e AES -k 256 -m SHA256withRSA -n pa-user --host localhost --port 1337".split(" ");
        this.client = new Client();
        new CommandLine(this.client).parseArgs(args);
        this.client.setEncryptionAlgorithmType(EncryptionAlgorithmType.SYMMETRIC);
        KeyPair clientSigningKeys = AsymmetricEncryptionScheme.generateKeys(4096);
        KeyPair serverSigningKeys = AsymmetricEncryptionScheme.generateKeys(4096);
        this.client.setServerSigningKey(serverSigningKeys.getPublic());
        BigInteger symmetricEncryptionKey = DiffieHellman.generatePrivateKey();
        this.client.setSymmetricEncryptionKey(symmetricEncryptionKey);
        this.client.setSigningKeys(clientSigningKeys);
    }

    @Test
    @DisplayName("Should be able to extract the message")
    void testGetMessage() throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException,
            BadPaddingException, SignatureException, InvalidKeyException {
        ClientMessage clientMessage = new ClientMessage(messageMultipleUsers, this.client);
        byte[] message = clientMessage.getMessage();
        byte[] expected = Encoder.encodeMessage("Hello World", this.client);
        assertArrayEquals(message, expected);
    }

    @Test
    @DisplayName("Should be able to get all the clients")
    void testGetMultipleClients() throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException,
            BadPaddingException, SignatureException, InvalidKeyException {
        ClientMessage clientMessage = new ClientMessage(messageMultipleUsers, this.client);
        HashSet<String> users = clientMessage.getUsers();
        HashSet<String> expectedUsers = new HashSet<>(Arrays.asList("user1", "user2", "user3"));
        assertEquals(users, expectedUsers);
    }

    @Test
    @DisplayName("Should be able to get client if there is only one client")
    void testGetOneClient() throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException,
            BadPaddingException, SignatureException, InvalidKeyException {
        String messageSingleUser = "@user1 Hello World";
        ClientMessage clientMessage = new ClientMessage(messageSingleUser, this.client);
        HashSet<String> user = clientMessage.getUsers();
        HashSet<String> expectedUser = new HashSet<>(Collections.singletonList("user1"));
        assertEquals(user, expectedUser);
    }

    @Test
    @DisplayName("Should be able to detect if it's a broadcast message")
    void testBroadcast() throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException,
            BadPaddingException, SignatureException, InvalidKeyException {
        ClientMessage clientMessage = new ClientMessage(messageBroadcast, client);
        HashSet<String> broadcast = clientMessage.getUsers();
        HashSet<String> expectedResult = new HashSet<>();
        assertEquals(broadcast, expectedResult);
    }

    @Test
    @DisplayName("Should be able to get the signature value")
    void testGetSignature() throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException,
            BadPaddingException, SignatureException, InvalidKeyException {
        ClientMessage clientMessage = new ClientMessage(messageBroadcast, client);
        byte[] expected = Encoder.createSignature(messageBroadcast, this.client.getHashingAlgorithm(),
                                                  this.client.getSigningKeys()
                                                              .getPrivate());
        assertArrayEquals(clientMessage.getSignature(), expected);
    }
}
